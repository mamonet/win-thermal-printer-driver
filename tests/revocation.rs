// tests/revocation.rs
// A revoked identity is denied on the VERY NEXT request. The gateway holds no
// cached grant; it re-reads the ledger per request, so a revoke committed
// between two calls flips the second to deny.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use zt_policy_gateway::audit::{AuditRecord, AuditSink};
use zt_policy_gateway::enforce::{Enforcer, Outcome};
use zt_policy_gateway::error::GatewayError;
use zt_policy_gateway::identity::Identity;
use zt_policy_gateway::policy::{Decision, PolicyClient};
use zt_policy_gateway::upstream::Upstream;

// Ledger whose current decision can be flipped mid-test (simulates a Revoke tx).
struct FlippablePolicy {
    revoked: Arc<Mutex<bool>>,
}

#[async_trait]
impl PolicyClient for FlippablePolicy {
    async fn evaluate(&self, _id: &Identity, _action: &str, _ctx: &str) -> Result<Decision, GatewayError> {
        // Read live state on every call. No caching anywhere.
        if *self.revoked.lock().unwrap() {
            Ok(Decision { allow: false, reason: "rule revoked".into(), policy_version: "/orders@v2".into() })
        } else {
            Ok(Decision { allow: true, reason: "allowed by rule".into(), policy_version: "/orders@v1".into() })
        }
    }
}

#[derive(Clone, Default)]
struct CountingUpstream {
    forwards: Arc<Mutex<u32>>,
}

#[async_trait]
impl Upstream for CountingUpstream {
    async fn forward(&self, _id: &Identity, _action: &str, _body: &[u8]) -> Result<Vec<u8>, GatewayError> {
        *self.forwards.lock().unwrap() += 1;
        Ok(b"ok".to_vec())
    }
}

#[derive(Clone, Default)]
struct VecAudit {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

#[async_trait]
impl AuditSink for VecAudit {
    async fn record(&self, rec: AuditRecord) -> Result<(), GatewayError> {
        self.records.lock().unwrap().push(rec);
        Ok(())
    }
}

fn alice() -> Identity {
    Identity { subject: "CN=alice,OU=client,O=Org1".into(), spki_sha256: "b".repeat(64), issuer: "CN=ca-org1".into() }
}

#[tokio::test]
async fn revoked_identity_denied_on_next_request() {
    let revoked = Arc::new(Mutex::new(false));
    let upstream = CountingUpstream::default();
    let audit = VecAudit::default();
    let enforcer = Enforcer::new(FlippablePolicy { revoked: revoked.clone() }, audit.clone(), upstream.clone());

    // First request: allowed.
    let first = enforcer.handle(&alice(), "GET", "/orders", b"x").await.unwrap();
    assert!(matches!(first, Outcome::Allowed(_)));
    assert_eq!(*upstream.forwards.lock().unwrap(), 1);

    // Revoke happens on the ledger (out of band).
    *revoked.lock().unwrap() = true;

    // Next request: denied immediately, no cached grant, upstream untouched.
    let second = enforcer.handle(&alice(), "GET", "/orders", b"x").await.unwrap();
    assert!(matches!(second, Outcome::Denied(_)));
    assert_eq!(*upstream.forwards.lock().unwrap(), 1, "no new forward after revoke");

    let recs = audit.records.lock().unwrap();
    assert_eq!(recs.last().unwrap().decision, "deny");
    assert_eq!(recs.last().unwrap().policy_version, "/orders@v2");
}
