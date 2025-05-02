// repo: gateway/src/enforce.rs
use crate::identity::Identity;
use crate::policy::{EvalContext, PolicyClient};
use crate::upstream::Upstream;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;

// The enforcement path: identity -> policy.evaluate -> forward on allow,
// 403 on deny. The gateway enforces the ledger's answer, nothing else.
#[derive(Clone)]
pub struct Enforcer {
    pub policy: Arc<dyn PolicyClient + Send + Sync>,
    pub upstream: Upstream,
}

impl Enforcer {
    // `identity` is the verified client identity from the mTLS layer.
    pub async fn handle(
        &self,
        identity: Identity,
        req: Request<Body>,
    ) -> Response<Body> {
        let action = format!("{} {}", req.method(), req.uri().path());
        let ctx = EvalContext {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
        };

        let decision = self.policy.evaluate(&identity, &action, &ctx);

        if decision.allow {
            match self.upstream.forward(req).await {
                Ok(resp) => resp,
                Err(_) => deny_response("upstream error"),
            }
        } else {
            deny_response(&decision.reason)
        }
    }
}

fn deny_response(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(format!("denied: {reason}")))
        .unwrap()
}
