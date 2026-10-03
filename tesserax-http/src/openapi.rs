//! OpenAPI 3.1 document generated from a [`RouteTable`].
//!
//! The document is a pure transform of the table the server serves, so it
//! cannot drift from it: one operation per `(method, path)`, the entry's
//! `label` (the route description) as `summary`, the tier and scope as the
//! `x-tier` / `x-scope` extensions, path parameters from `{name}`
//! segments, and per-operation `security` (an empty requirement for
//! `Public` routes, the configured schemes otherwise). Parameter and
//! response bodies are not inferred.
//!
//! [`HttpExt::with_openapi`](crate::HttpExt::with_openapi) serves the
//! document built from the server's *final* table (read per request from
//! the `Arc<RouteTable>` extension the root injects), so routes added by
//! any plugin appear.

use serde_json::{Map, Value, json};
use tesserax::{RouteEntry, RouteTable, Tier};

/// A security scheme advertised in `components.securitySchemes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityScheme {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// A cookie with this name.
    Cookie(String),
    /// A request header with this name.
    ApiKeyHeader(String),
}

impl SecurityScheme {
    fn name(&self) -> &'static str {
        match self {
            SecurityScheme::Bearer => "bearer",
            SecurityScheme::Cookie(_) => "cookie",
            SecurityScheme::ApiKeyHeader(_) => "api_key",
        }
    }

    fn to_json(&self) -> Value {
        match self {
            SecurityScheme::Bearer => json!({"type": "http", "scheme": "bearer"}),
            SecurityScheme::Cookie(n) => json!({"type": "apiKey", "in": "cookie", "name": n}),
            SecurityScheme::ApiKeyHeader(n) => json!({"type": "apiKey", "in": "header", "name": n}),
        }
    }
}

/// Inputs of [`build_openapi`].
#[derive(Clone, Copy, Debug)]
pub struct OpenApiInput<'a> {
    /// `info.title`.
    pub title: &'a str,
    /// `info.version` (`0.0.0` when absent).
    pub version: Option<&'a str>,
    /// `info.description`.
    pub description: Option<&'a str>,
    /// The routes.
    pub table: &'a RouteTable,
    /// Schemes any non-public route accepts (any one of them suffices).
    pub security: &'a [SecurityScheme],
    /// `servers[0].url`.
    pub server_url: Option<&'a str>,
}

/// Builds the OpenAPI 3.1 document.
pub fn build_openapi(input: OpenApiInput<'_>) -> Value {
    let mut info = Map::new();
    info.insert("title".into(), input.title.into());
    info.insert("version".into(), input.version.unwrap_or("0.0.0").into());
    if let Some(d) = input.description {
        info.insert("description".into(), d.into());
    }

    let mut paths: Map<String, Value> = Map::new();
    for r in input.table.iter() {
        let (openapi_path, params) = openapi_path(&r.path);
        let item = paths
            .entry(openapi_path)
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(item) = item {
            item.insert(
                r.method.as_str().to_ascii_lowercase(),
                operation(r, &params, input.security),
            );
        }
    }

    let mut doc = Map::new();
    doc.insert("openapi".into(), "3.1.0".into());
    doc.insert("info".into(), Value::Object(info));
    if let Some(url) = input.server_url {
        doc.insert("servers".into(), json!([{ "url": url }]));
    }
    doc.insert("paths".into(), Value::Object(paths));
    if !input.security.is_empty() {
        let schemes: Map<String, Value> = input
            .security
            .iter()
            .map(|s| (s.name().to_owned(), s.to_json()))
            .collect();
        doc.insert(
            "components".into(),
            json!({ "securitySchemes": Value::Object(schemes) }),
        );
    }
    Value::Object(doc)
}

fn operation(r: &RouteEntry, params: &[String], security: &[SecurityScheme]) -> Value {
    let mut op = Map::new();
    let summary = r
        .label
        .clone()
        .unwrap_or_else(|| format!("{} {}", r.method, r.path));
    op.insert("summary".into(), summary.into());
    op.insert("operationId".into(), operation_id(r).into());
    op.insert("x-tier".into(), r.tier.as_str().into());
    if let Some(s) = &r.scope {
        op.insert("x-scope".into(), s.as_str().into());
    }
    if r.builtin {
        op.insert("x-builtin".into(), true.into());
    }
    if !params.is_empty() {
        let list: Vec<Value> = params
            .iter()
            .map(|p| json!({"name": p, "in": "path", "required": true, "schema": {"type": "string"}}))
            .collect();
        op.insert("parameters".into(), Value::Array(list));
    }
    if r.tier == Tier::Public && r.scope.is_none() {
        op.insert("security".into(), json!([{}]));
    } else if !security.is_empty() {
        let any_of: Vec<Value> = security.iter().map(|s| json!({ s.name(): [] })).collect();
        op.insert("security".into(), Value::Array(any_of));
    }
    let mut responses = Map::new();
    responses.insert("200".into(), json!({"description": "OK"}));
    if r.tier != Tier::Public || r.scope.is_some() {
        responses.insert(
            "401".into(),
            json!({"description": "Missing or refused credential"}),
        );
    }
    op.insert("responses".into(), Value::Object(responses));
    Value::Object(op)
}

/// `/items/{id}/{*rest}` → (`/items/{id}/{rest}`, `["id", "rest"]`).
fn openapi_path(template: &str) -> (String, Vec<String>) {
    let mut params = Vec::new();
    let segs: Vec<String> = template
        .split('/')
        .map(
            |seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(inner) => {
                    let name = inner.trim_start_matches('*').to_owned();
                    params.push(name.clone());
                    format!("{{{name}}}")
                }
                None => seg.to_owned(),
            },
        )
        .collect();
    (segs.join("/"), params)
}

fn operation_id(r: &RouteEntry) -> String {
    let path: String = r
        .path
        .trim_start_matches('/')
        .chars()
        .filter(|c| !matches!(c, '{' | '}' | '*'))
        .map(|c| if c == '/' { '_' } else { c })
        .collect();
    let path = if path.is_empty() {
        "root".to_owned()
    } else {
        path
    };
    format!("{}_{}", r.method.as_str().to_ascii_lowercase(), path)
}

/// A Swagger UI page that loads the document from `spec_url` (assets from
/// the public `unpkg.com` CDN).
pub fn swagger_ui_html(spec_url: &str, title: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({{
      url: '{spec_url}',
      dom_id: '#swagger-ui',
      deepLinking: true,
    }});
  </script>
</body>
</html>
"#,
        title = html_escape(title),
        spec_url = html_escape_attr(spec_url),
    )
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_escape_attr(s: &str) -> String {
    html_escape(s).replace('"', "&quot;").replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tesserax::{HttpMethod, Scope};

    fn table() -> RouteTable {
        let mut t = RouteTable::new();
        t.push(
            RouteEntry::new(HttpMethod::Get, "/ping", Tier::Public).with_label("Liveness probe"),
        );
        t.push(
            RouteEntry::new(HttpMethod::Post, "/api/v1/upload", Tier::Admin)
                .with_label("Push a release"),
        );
        t.push(
            RouteEntry::new(HttpMethod::Get, "/items/{id}/{*rest}", Tier::Authenticated)
                .with_scope(Scope::new("items.read").unwrap()),
        );
        t
    }

    fn doc(security: &[SecurityScheme]) -> Value {
        let t = table();
        build_openapi(OpenApiInput {
            title: "svc",
            version: Some("0.1.0"),
            description: None,
            table: &t,
            security,
            server_url: Some("http://127.0.0.1:8080"),
        })
    }

    #[test]
    fn envelope_and_every_route() {
        let d = doc(&[SecurityScheme::Bearer]);
        assert_eq!(d["openapi"], "3.1.0");
        assert_eq!(d["info"]["title"], "svc");
        assert_eq!(d["info"]["version"], "0.1.0");
        assert_eq!(d["servers"][0]["url"], "http://127.0.0.1:8080");
        assert_eq!(d["paths"]["/ping"]["get"]["summary"], "Liveness probe");
        assert_eq!(d["paths"]["/ping"]["get"]["x-tier"], "public");
        assert_eq!(d["paths"]["/api/v1/upload"]["post"]["x-tier"], "admin");
        assert_eq!(
            d["paths"]["/api/v1/upload"]["post"]["operationId"],
            "post_api_v1_upload"
        );
    }

    #[test]
    fn path_parameters_and_scope() {
        let d = doc(&[]);
        let op = &d["paths"]["/items/{id}/{rest}"]["get"];
        assert_eq!(op["parameters"][0]["name"], "id");
        assert_eq!(op["parameters"][1]["name"], "rest");
        assert_eq!(op["x-scope"], "items.read");
        assert_eq!(op["summary"], "GET /items/{id}/{*rest}");
        assert_eq!(op["operationId"], "get_items_id_rest");
    }

    #[test]
    fn security_per_operation() {
        let d = doc(&[
            SecurityScheme::Bearer,
            SecurityScheme::Cookie("session".into()),
        ]);
        let public = d["paths"]["/ping"]["get"]["security"].as_array().unwrap();
        assert_eq!(public.len(), 1);
        assert!(public[0].as_object().unwrap().is_empty());
        let admin = d["paths"]["/api/v1/upload"]["post"]["security"]
            .as_array()
            .unwrap();
        assert_eq!(admin.len(), 2);
        assert!(admin[0].get("bearer").is_some());
        assert_eq!(
            d["components"]["securitySchemes"]["bearer"]["scheme"],
            "bearer"
        );
        assert_eq!(d["components"]["securitySchemes"]["cookie"]["in"], "cookie");
        assert!(doc(&[]).get("components").is_none());
    }

    #[test]
    fn swagger_ui_escapes() {
        let html = swagger_ui_html("/openapi.json", "svc API");
        assert!(html.contains("'/openapi.json'"));
        let html = swagger_ui_html("/a\"b", "<bad>");
        assert!(!html.contains("<bad>"));
        assert!(html.contains("&lt;bad&gt;"));
        assert!(html.contains("&quot;"));
    }
}
