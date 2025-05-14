// repo: gateway/src/enforce.rs
use crate::audit::{build_record, AuditSink};
use crate::identity::Identity;
use crate::policy::{EvalContext, PolicyClient};
use crate::upstream::Upstream;
use hyper::body::to_bytes;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;

// identity -> policy.evaluate -> audit.record -> act.
// Strict ordering: DECIDE, then RECORD, then (only then) ACT.
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

        let (parts, body) = req.into_parts();
        let bytes = match to_bytes(body).await {
            Ok(b) => b,
            Err(_) => return deny_response("could not read request body"),
        };

        let decision = self.policy.evaluate(&identity, &action, &ctx);

        // Record before acting, for both outcomes. Only the body hash is stored.
        let rec = build_record(&identity, &action, &bytes, &decision);

        // FIX: previously the audit write result was ignored (`let _ = ...`), so
        // a failed record could still be followed by a forward. That produces an
        // action with no immutable proof it was authorized. If we cannot record
        // the decision, we DENY, even when the policy said allow. An
        // unrecordable decision is treated exactly like a ledger failure:
        // FAIL CLOSED. Ordering is load-bearing: decide, record, only then act.
        if let Err(e) = self.audit.record(&rec) {
            return deny_response(&format!("audit unavailable, failing closed: {e}"));
        }

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
