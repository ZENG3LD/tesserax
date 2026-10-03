//! [`TelegramBot`]: outbound Telegram Bot API calls over raw HTTPS.
//!
//! The bot token is part of every request URL, so transport errors are
//! reported without their URL and `Debug` never prints the token.

use std::time::Duration;

use serde_json::{Value, json};

use super::{USER_AGENT, clip};

/// Bot API base; the token and method follow.
const DEFAULT_API_BASE: &str = "https://api.telegram.org";

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    /// Transport or decoding failure (URL stripped).
    #[error("http: {0}")]
    Http(#[source] reqwest::Error),
    /// The API answered `ok: false`, or not JSON.
    #[error("api: {0}")]
    Api(String),
}

impl From<reqwest::Error> for TelegramError {
    fn from(e: reqwest::Error) -> Self {
        TelegramError::Http(e.without_url())
    }
}

/// A bot identified by its token.
pub struct TelegramBot {
    client: reqwest::Client,
    base: String,
    token: String,
}

impl std::fmt::Debug for TelegramBot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramBot")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl TelegramBot {
    /// A bot with `token`, 30 s per call, against `https://api.telegram.org`.
    pub fn new(token: impl Into<String>) -> Result<Self, TelegramError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(TelegramError::from)?;
        Ok(Self {
            client,
            base: DEFAULT_API_BASE.to_owned(),
            token: token.into(),
        })
    }

    /// Another API base (a local Bot API server, a test double); no
    /// trailing slash.
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_owned();
        self
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base, self.token)
    }

    /// `getMe`: the bot's username.
    pub async fn verify(&self) -> Result<String, TelegramError> {
        let body: Value = self
            .client
            .get(self.url("getMe"))
            .send()
            .await?
            .json()
            .await?;
        let result = ok_result(body)?;
        Ok(result
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned())
    }

    /// `sendMessage` with `parse_mode: HTML`.
    pub async fn send_message(
        &self,
        chat_id: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<(), TelegramError> {
        let body = json!({
            "chat_id": chat_id.into(),
            "text": text.into(),
            "parse_mode": "HTML",
        });
        self.post("sendMessage", &body).await
    }

    /// `sendPhoto` by URL with an optional caption.
    pub async fn send_photo(
        &self,
        chat_id: impl Into<String>,
        photo_url: impl Into<String>,
        caption: Option<&str>,
    ) -> Result<(), TelegramError> {
        let mut body = json!({
            "chat_id": chat_id.into(),
            "photo": photo_url.into(),
        });
        if let Some(c) = caption {
            body["caption"] = Value::String(c.to_owned());
        }
        self.post("sendPhoto", &body).await
    }

    async fn post(&self, method: &str, body: &Value) -> Result<(), TelegramError> {
        let resp = self.client.post(self.url(method)).json(body).send().await?;
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|_| TelegramError::Api(format!("not JSON: {}", clip(text))))?;
        ok_result(v).map(|_| ())
    }
}

fn ok_result(body: Value) -> Result<Value, TelegramError> {
    if body.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(TelegramError::Api(
            body.get("description")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_constructs_and_hides_the_token() {
        let b = TelegramBot::new("123:ABC").unwrap();
        assert!(!format!("{b:?}").contains("123:ABC"));
        assert_eq!(b.url("getMe"), "https://api.telegram.org/bot123:ABC/getMe");
        let b = b.with_api_base("http://127.0.0.1:9/");
        assert_eq!(b.url("getMe"), "http://127.0.0.1:9/bot123:ABC/getMe");
    }

    #[test]
    fn api_errors_carry_the_description() {
        let e = ok_result(json!({"ok": false, "description": "chat not found"})).unwrap_err();
        assert_eq!(e.to_string(), "api: chat not found");
        assert_eq!(
            ok_result(json!({"ok": true, "result": 5})).unwrap(),
            json!(5)
        );
    }
}
