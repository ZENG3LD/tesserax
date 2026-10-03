//! [`IpAcl`]: allow / deny lists on the caller's honest address.
//!
//! Deny is checked first and wins. With an allow list, only addresses in
//! it pass, and an empty allow list admits nobody; without one, everything
//! not denied passes. Refusal: `403 {"ok":false,"error":"ip_not_admitted"}`.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tesserax::CidrList;

use super::{client_ip, refuse};

/// Allow / deny lists. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct IpAcl {
    allow: Option<Arc<CidrList>>,
    deny: Arc<CidrList>,
    trusted_proxies: Arc<CidrList>,
}

impl IpAcl {
    /// Only addresses in `allow` pass (an empty list admits nobody).
    pub fn allow_only(allow: CidrList) -> Self {
        Self {
            allow: Some(Arc::new(allow)),
            ..Self::default()
        }
    }

    /// Addresses in `deny` are refused, all others pass.
    pub fn deny_only(deny: CidrList) -> Self {
        Self {
            deny: Arc::new(deny),
            ..Self::default()
        }
    }

    /// Both lists; deny wins.
    pub fn allow_and_deny(allow: CidrList, deny: CidrList) -> Self {
        Self {
            allow: Some(Arc::new(allow)),
            deny: Arc::new(deny),
            ..Self::default()
        }
    }

    /// Proxies whose forwarding headers are believed.
    pub fn trusted_proxies(mut self, list: CidrList) -> Self {
        self.trusted_proxies = Arc::new(list);
        self
    }

    /// The decision for `ip`.
    pub fn admits(&self, ip: IpAddr) -> bool {
        if self.deny.matches(ip) {
            return false;
        }
        self.allow.as_ref().is_none_or(|a| a.matches(ip))
    }
}

/// The middleware (`from_fn_with_state(acl, ip_acl_mw)`).
pub async fn ip_acl_mw(State(acl): State<IpAcl>, req: Request, next: Next) -> Response {
    let ip = client_ip(&req, &acl.trusted_proxies);
    if acl.admits(ip) {
        next.run(req).await
    } else {
        tracing::warn!(%ip, "ip acl refused");
        refuse(StatusCode::FORBIDDEN, "ip_not_admitted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn list(s: &str) -> CidrList {
        CidrList::parse(s).unwrap()
    }

    #[test]
    fn decisions() {
        assert!(IpAcl::deny_only(CidrList::new()).admits(ip("192.0.2.4")));
        let a = IpAcl::allow_only(list("10.0.0.0/8"));
        assert!(a.admits(ip("10.1.2.3")));
        assert!(!a.admits(ip("198.51.100.8")));
        assert!(!IpAcl::allow_only(CidrList::new()).admits(ip("10.1.2.3")));
        let d = IpAcl::deny_only(list("203.0.113.6"));
        assert!(!d.admits(ip("203.0.113.6")));
        assert!(d.admits(ip("192.0.2.4")));
        let both = IpAcl::allow_and_deny(list("10.0.0.0/8"), list("10.0.0.5"));
        assert!(both.admits(ip("10.0.0.1")));
        assert!(!both.admits(ip("10.0.0.5")));
        assert!(!both.admits(ip("198.51.100.8")));
    }
}
