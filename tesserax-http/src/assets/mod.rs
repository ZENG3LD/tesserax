//! Static assets: a directory server ([`StaticDir`]), the cross-origin
//! isolation headers a wasm page needs ([`wasm_headers`]) and a single
//! inline HTML page ([`Dashboard`]).

mod dashboard;
mod static_dir;
mod wasm;

pub use dashboard::Dashboard;
pub use static_dir::StaticDir;
pub use wasm::wasm_headers;
