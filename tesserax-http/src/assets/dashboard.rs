//! [`Dashboard`]: one self-contained HTML page (inline CSS / JS calling the
//! server's own API) served from memory.

use std::sync::Arc;

use axum::response::{Html, IntoResponse, Response};

use crate::openapi::html_escape;

/// An in-memory HTML page. Cheap to clone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dashboard {
    title: Arc<str>,
    html: Arc<str>,
}

impl Dashboard {
    /// A complete document supplied by the caller.
    pub fn from_html(title: impl Into<String>, html: impl Into<String>) -> Self {
        Self {
            title: Arc::from(title.into().as_str()),
            html: Arc::from(html.into().as_str()),
        }
    }

    /// `body` wrapped in a minimal UTF-8 document titled `title` (escaped).
    pub fn from_body(title: impl Into<String>, body: impl AsRef<str>) -> Self {
        let title = title.into();
        let html = format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <title>{}</title>\n</head>\n<body>\n{}\n</body>\n</html>\n",
            html_escape(&title).replace('"', "&quot;"),
            body.as_ref(),
        );
        Self::from_html(title, html)
    }

    /// The title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The document.
    pub fn html(&self) -> &str {
        &self.html
    }

    /// `200 text/html`.
    pub fn render(&self) -> Response {
        Html(self.html.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_escapes_title() {
        let d = Dashboard::from_body("Ops <Panel> & Co", "<h1>hi</h1>");
        assert_eq!(d.title(), "Ops <Panel> & Co");
        assert!(
            d.html()
                .contains("<title>Ops &lt;Panel&gt; &amp; Co</title>")
        );
        assert!(d.html().contains("<h1>hi</h1>"));
        assert!(d.render().status().is_success());
        assert_eq!(Dashboard::from_html("X", "<p>raw</p>").html(), "<p>raw</p>");
    }
}
