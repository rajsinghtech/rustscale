//! Control-to-Node (C2N) request routing.
//!
//! The control plane sends HTTP requests through the Noise control channel to
//! a node to probe liveness or invoke debug handlers. The C2N router
//! dispatches incoming requests to registered handlers keyed by URL path.
//!
//! Ports the handler registry pattern from Go's `ipn/ipnlocal/c2n.go`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

/// A single C2N request, as received from the control plane over the Noise
/// channel. The path is the URL path without query parameters.
#[derive(Debug, Clone)]
pub struct C2nRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// A C2N response sent back over the Noise channel.
#[derive(Debug, Clone)]
pub struct C2nResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl C2nResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }

    pub fn error(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            body: msg.into().into_bytes(),
        }
    }
}

/// A C2N handler processes a single request and returns a response.
#[async_trait]
pub trait C2nHandler: Send + Sync {
    async fn handle(&self, req: C2nRequest) -> C2nResponse;
}

/// Routes incoming C2N requests to registered handlers by URL path.
///
/// A handler registered with a specific method (e.g. `"POST /foo"`) is
/// preferred; if no method-specific match exists, a method-agnostic
/// registration (e.g. `"/foo"`) is used as a fallback. This mirrors Go's
/// `c2nHandlers` lookup in `handleC2N`.
#[derive(Default)]
pub struct C2nRouter {
    exact: HashMap<(String, String), Arc<dyn C2nHandler>>,
    fallback: HashMap<String, Arc<dyn C2nHandler>>,
}

impl C2nRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, pattern: &str, handler: Arc<dyn C2nHandler>) {
        if let Some((method, path)) = pattern.split_once(' ') {
            self.exact.insert((method.to_string(), path.to_string()), handler);
        } else {
            self.fallback.insert(pattern.to_string(), handler);
        }
    }

    pub async fn route(&self, req: C2nRequest) -> C2nResponse {
        if let Some(h) = self.exact.get(&(req.method.clone(), req.path.clone())) {
            return h.handle(req).await;
        }
        if let Some(h) = self.fallback.get(&req.path) {
            return h.handle(req).await;
        }
        let known_paths: std::collections::HashSet<&str> = self
            .exact
            .keys()
            .map(|(_, p)| p.as_str())
            .chain(self.fallback.keys().map(String::as_str))
            .collect();
        if known_paths.contains(req.path.as_str()) {
            C2nResponse::error(405, "bad method")
        } else {
            C2nResponse::error(400, "unknown c2n path")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoHandler;

    #[async_trait]
    impl C2nHandler for EchoHandler {
        async fn handle(&self, req: C2nRequest) -> C2nResponse {
            C2nResponse::ok(req.body)
        }
    }

    #[tokio::test]
    async fn echo_returns_body_unchanged() {
        let handler = Arc::new(EchoHandler);
        let resp = handler
            .handle(C2nRequest {
                method: "GET".into(),
                path: "/echo".into(),
                body: b"hello".to_vec(),
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }

    #[tokio::test]
    async fn router_dispatches_to_registered_handler() {
        let mut router = C2nRouter::new();
        router.register("/echo", Arc::new(EchoHandler));

        let resp = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/echo".into(),
                body: b"ping".to_vec(),
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ping");
    }

    #[tokio::test]
    async fn router_unknown_path_returns_400() {
        let router = C2nRouter::new();
        let resp = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/nope".into(),
                body: vec![],
            })
            .await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test]
    async fn router_method_mismatch_returns_405() {
        let mut router = C2nRouter::new();
        router.register("POST /flush", Arc::new(EchoHandler));

        let resp = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/flush".into(),
                body: vec![],
            })
            .await;
        assert_eq!(resp.status, 405);
    }

    #[tokio::test]
    async fn router_exact_match_preferred_over_fallback() {
        struct PostHandler;
        #[async_trait]
        impl C2nHandler for PostHandler {
            async fn handle(&self, _req: C2nRequest) -> C2nResponse {
                C2nResponse::ok(b"post".to_vec())
            }
        }

        let mut router = C2nRouter::new();
        router.register("/echo", Arc::new(EchoHandler));
        router.register("POST /echo", Arc::new(PostHandler));

        let resp = router
            .route(C2nRequest {
                method: "POST".into(),
                path: "/echo".into(),
                body: vec![],
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"post");

        let resp = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/echo".into(),
                body: b"hi".to_vec(),
            })
            .await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hi");
    }
}
