// repo: gateway/src/enforce.rs
use crate::audit::{build_record, AuditSink};
use crate::identity::Identity;
use crate::policy::{EvalContext, PolicyClient};
use crate::upstream::Upstream;
use hyper::body::to_bytes;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;

// identity -> policy.evaluate -> audit.record -> act. Audit is written for
// BOTH allow and deny so every decision leaves a trail.
#[derive(Clone)]
pub struct Enforcer {
    pub policy: Arc<dyn PolicyClient + Send + Sync>,
    pub audit: Arc<dyn AuditSink + Send + Sync>,
    pub upstream: Upstream,
}

impl Enforcer {
    pub async fn handle(&self, identity: Identity, req: Request<Body>) -> Response<Body> {
        let action = format!("{} {}", req.method(), req.uri().path());
        let ctx = EvalContext {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
        };

        // Buffer the body so we can hash it for audit and still forward it.
        let (parts, body) = req.into_parts();
        let bytes = match to_bytes(body).await {
            Ok(b) => b,
            Err(_) => return deny_response("could not read request body"),
        };

        let decision = self.policy.evaluate(&identity, &action, &ctx);

        // Record before acting, for both outcomes. Only the body hash goes in.
        let rec = build_record(&identity, &action, &bytes, &decision);
        let _ = self.audit.record(&rec);

        if decision.allow {
            let fwd = Request::from_parts(parts, Body::from(bytes));
            match self.upstream.forward(fwd).await {
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
