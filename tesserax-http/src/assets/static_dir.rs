//! [`StaticDir`]: serve a directory (`tower_http::services::ServeDir`).
//!
//! ```no_run
//! use tesserax_http::assets::StaticDir;
//!
//! let web = StaticDir::new("./web").with_spa_fallback("./web/index.html");
//! let router: axum::Router = web.into_router();
//! ```

use std::path::{Path, PathBuf};

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fallback {
    None,
    /// Served with 200 (single-page apps with client-side routes).
    Spa(PathBuf),
    /// Served with 404.
    NotFound(PathBuf),
}

/// A directory to serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticDir {
    root: PathBuf,
    index_html: bool,
    fallback: Fallback,
}

impl StaticDir {
    /// Serves `root`; `index.html` is appended for directories.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            index_html: true,
            fallback: Fallback::None,
        }
    }

    /// Does not append `index.html` for directories.
    pub fn without_index_html(mut self) -> Self {
        self.index_html = false;
        self
    }

    /// Unresolved paths get this file with status 200.
    pub fn with_spa_fallback(mut self, file: impl Into<PathBuf>) -> Self {
        self.fallback = Fallback::Spa(file.into());
        self
    }

    /// Unresolved paths get this file with status 404.
    pub fn with_not_found(mut self, file: impl Into<PathBuf>) -> Self {
        self.fallback = Fallback::NotFound(file.into());
        self
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A router that serves the directory from its fallback (so it never
    /// shadows explicit routes it is merged with).
    pub fn into_router(self) -> Router {
        let dir = ServeDir::new(&self.root).append_index_html_on_directories(self.index_html);
        match self.fallback {
            Fallback::None => Router::new().fallback_service(dir),
            Fallback::Spa(f) => Router::new().fallback_service(dir.fallback(ServeFile::new(f))),
            Fallback::NotFound(f) => {
                Router::new().fallback_service(dir.not_found_service(ServeFile::new(f)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::StatusCode;
    use tower::ServiceExt;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("tesserax-http-static-{}", std::process::id()));
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(d.join("sub/index.html"), "<h1>sub</h1>").unwrap();
        std::fs::write(d.join("404.html"), "gone").unwrap();
        d
    }

    async fn get(r: Router, uri: &str) -> (StatusCode, String) {
        let resp = r
            .oneshot(axum::http::Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let s = resp.status();
        (
            s,
            String::from_utf8(to_bytes(resp.into_body(), 4096).await.unwrap().to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn serves_index_and_fallbacks() {
        let d = tmp();
        assert_eq!(
            get(StaticDir::new(&d).into_router(), "/sub/").await.1,
            "<h1>sub</h1>"
        );
        assert_eq!(
            get(StaticDir::new(&d).into_router(), "/nope").await.0,
            StatusCode::NOT_FOUND
        );
        let spa = StaticDir::new(&d).with_spa_fallback(d.join("index.html"));
        assert_eq!(
            get(spa.into_router(), "/app/route").await,
            (StatusCode::OK, "<h1>home</h1>".into())
        );
        let nf = StaticDir::new(&d).with_not_found(d.join("404.html"));
        assert_eq!(
            get(nf.into_router(), "/x").await,
            (StatusCode::NOT_FOUND, "gone".into())
        );
        assert_eq!(StaticDir::new(&d).without_index_html().root(), d.as_path());
    }
}
