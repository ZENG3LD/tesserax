//! `Webhook` and `TelegramBot` against an in-test HTTP server.
#![cfg(all(feature = "egress", feature = "server"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tesserax_http::guard::WebhookVerifier;
use tesserax_transport::egress::{
    TelegramBot, TelegramError, Webhook, WebhookError, WebhookRetryPolicy,
};

const SECRET: &[u8] = b"shared-webhook-secret";
const TOKEN: &str = "123456:TEST-token";

#[derive(Clone, Default)]
struct Hits {
    flaky: Arc<AtomicUsize>,
    always: Arc<AtomicUsize>,
    bad: Arc<AtomicUsize>,
    busy: Arc<AtomicUsize>,
}

async fn serve(router: Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    addr
}

fn fast() -> WebhookRetryPolicy {
    WebhookRetryPolicy {
        attempts: 3,
        initial_delay: Duration::from_millis(5),
        backoff_factor: 2.0,
        max_delay: Duration::from_millis(20),
    }
}

async fn hooks() -> (SocketAddr, Hits) {
    let hits = Hits::default();
    let router = Router::new()
        .route("/ok", post(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/flaky",
            post(|State(h): State<Hits>| async move {
                if h.flaky.fetch_add(1, Ordering::SeqCst) < 2 {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/always500",
            post(|State(h): State<Hits>| async move {
                h.always.fetch_add(1, Ordering::SeqCst);
                (StatusCode::INTERNAL_SERVER_ERROR, "down")
            }),
        )
        .route(
            "/busy",
            post(|State(h): State<Hits>| async move {
                if h.busy.fetch_add(1, Ordering::SeqCst) == 0 {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/bad",
            post(|State(h): State<Hits>| async move {
                h.bad.fetch_add(1, Ordering::SeqCst);
                (StatusCode::UNPROCESSABLE_ENTITY, "bad body")
            }),
        )
        .route(
            "/redirect",
            post(|| async { (StatusCode::FOUND, [("location", "/ok")]) }),
        )
        .route(
            "/signed",
            post(|headers: HeaderMap, body: Bytes| async move {
                match WebhookVerifier::new(SECRET.to_vec()).verify(&headers, &body) {
                    Ok(()) if body.as_ref() == br#"{"event":"deploy","n":1}"# => {
                        StatusCode::NO_CONTENT
                    }
                    Ok(()) => StatusCode::BAD_REQUEST,
                    Err(s) => s,
                }
            }),
        )
        .with_state(hits.clone());
    (serve(router).await, hits)
}

#[tokio::test]
async fn webhook_delivers_and_retries_only_what_is_retryable() {
    let (addr, hits) = hooks().await;
    let hook = |p: &str| {
        Webhook::new(format!("http://{addr}{p}"))
            .unwrap()
            .with_policy(fast())
    };
    let body = json!({"event": "deploy", "n": 1});

    hook("/ok").post_json(&body).await.unwrap();

    hook("/flaky").post_json(&body).await.unwrap();
    assert_eq!(
        hits.flaky.load(Ordering::SeqCst),
        3,
        "two 502s retried, third attempt wins"
    );

    hook("/busy").post_json(&body).await.unwrap();
    assert_eq!(hits.busy.load(Ordering::SeqCst), 2, "429 is retried");

    let err = hook("/always500").post_json(&body).await.unwrap_err();
    assert!(
        matches!(err, WebhookError::ServerError { status: 500, ref body } if body == "down"),
        "{err:?}"
    );
    assert_eq!(hits.always.load(Ordering::SeqCst), 3);

    let err = hook("/bad").post_json(&body).await.unwrap_err();
    assert!(
        matches!(err, WebhookError::Rejected { status: 422, .. }),
        "{err:?}"
    );
    assert_eq!(hits.bad.load(Ordering::SeqCst), 1, "a 4xx is final");

    let err = hook("/redirect").post_json(&body).await.unwrap_err();
    assert!(
        matches!(err, WebhookError::Rejected { status: 302, .. }),
        "redirects are not followed: {err:?}"
    );
}

#[tokio::test]
async fn signed_webhook_passes_the_http_crate_verifier() {
    let (addr, _) = hooks().await;
    let url = format!("http://{addr}/signed");
    let body = json!({"event": "deploy", "n": 1});
    Webhook::new(&url)
        .unwrap()
        .with_policy(fast())
        .with_signing_secret(SECRET.to_vec())
        .post_json(&body)
        .await
        .unwrap();

    let err = Webhook::new(&url)
        .unwrap()
        .with_policy(fast())
        .with_signing_secret(b"another-secret".to_vec())
        .post_json(&body)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WebhookError::Rejected { status: 401, .. }),
        "{err:?}"
    );

    let err = Webhook::new(&url)
        .unwrap()
        .with_policy(fast())
        .post_json(&body)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WebhookError::Rejected { status: 401, .. }),
        "unsigned: {err:?}"
    );
}

#[tokio::test]
async fn webhook_transport_failure_exhausts_the_attempts() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let err = Webhook::new(format!("http://{addr}/gone"))
        .unwrap()
        .with_policy(fast())
        .post_json(&json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, WebhookError::Exhausted(_)), "{err:?}");
    assert!(
        !err.to_string().contains("/gone"),
        "URL stays out of the error: {err}"
    );
}

async fn bot_api() -> SocketAddr {
    let router = Router::new()
        .route(
            "/{bot}/getMe",
            get(|Path(bot): Path<String>| async move {
                if bot == format!("bot{TOKEN}") {
                    Json(json!({"ok": true, "result": {"username": "notify_bot"}}))
                } else {
                    Json(json!({"ok": false, "description": "Unauthorized"}))
                }
            }),
        )
        .route(
            "/{bot}/sendMessage",
            post(|Json(v): Json<Value>| async move {
                let good =
                    v["chat_id"] == "42" && v["text"] == "<b>up</b>" && v["parse_mode"] == "HTML";
                if good {
                    Json(json!({"ok": true, "result": {}}))
                } else {
                    Json(json!({"ok": false, "description": "Bad Request: chat not found"}))
                }
            }),
        )
        .route(
            "/{bot}/sendPhoto",
            post(|Json(v): Json<Value>| async move {
                let good = v["photo"] == "https://example.com/p.png" && v["caption"] == "chart";
                Json(json!({"ok": good, "description": "bad photo"}))
            }),
        );
    serve(router).await
}

#[tokio::test]
async fn telegram_calls_reach_the_api_and_report_its_errors() {
    let addr = bot_api().await;
    let bot = TelegramBot::new(TOKEN)
        .unwrap()
        .with_api_base(format!("http://{addr}"));
    assert_eq!(bot.verify().await.unwrap(), "notify_bot");
    bot.send_message("42", "<b>up</b>").await.unwrap();
    bot.send_photo("42", "https://example.com/p.png", Some("chart"))
        .await
        .unwrap();
    let err = bot.send_message("7", "x").await.unwrap_err();
    assert_eq!(err.to_string(), "api: Bad Request: chat not found");

    let wrong = TelegramBot::new("999:nope")
        .unwrap()
        .with_api_base(format!("http://{addr}"));
    assert!(matches!(wrong.verify().await, Err(TelegramError::Api(ref d)) if d == "Unauthorized"));
}

#[tokio::test]
async fn telegram_transport_errors_never_show_the_token() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let bot = TelegramBot::new(TOKEN)
        .unwrap()
        .with_api_base(format!("http://{addr}"));
    let err = bot.send_message("42", "x").await.unwrap_err();
    assert!(matches!(err, TelegramError::Http(_)));
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("TEST-token"), "{shown}");
}
