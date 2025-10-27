// tests/allow_deny.rs
// Allow and deny end to end with a MOCK ledger client. A deny is refused at the
// edge: the upstream is never called, and both outcomes are audited.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use zt_policy_gateway::audit::{AuditRecord, AuditSink};
use zt_policy_gateway::enforce::{Enforcer, Outcome};
use zt_policy_gateway::error::GatewayError;
use zt_policy_gateway::identity::Identity;
use zt_policy_gateway::policy::{Decision, PolicyClient};
use zt_policy_gateway::upstream::Upstream;

// Mock policy ledger: returns a canned decision, records the call.
struct MockPolicy {
    decision: Decision,
    calls: Arc<Mutex<Vec<(String, String)>>>, // (identity, action)
}

#[async_trait]
impl PolicyClient for MockPolicy {
    async fn evaluate(&self, id: &Identity, action: &str, _ctx: &str) -> Result<Decision, GatewayError> {
        self.calls.lock().unwrap().push((id.subject.clone(), action.into()));
        Ok(self.decision.clone())
    }
}

// Mock audit sink: captures every record written.
#[derive(Clone, Default)]
struct MockAudit {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

#[async_trait]
impl AuditSink for MockAudit {
    async fn record(&self, rec: AuditRecord) -> Result<(), GatewayError> {
        self.records.lock().unwrap().push(rec);
        Ok(())
    }
}

// Mock upstream: counts forwards so we can assert deny never reaches it.
#[derive(Clone, Default)]
struct MockUpstream {
    forwards: Arc<Mutex<u32>>,
}

#[async_trait]
impl Upstream for MockUpstream {
    async fn forward(&self, _id: &Identity, _action: &str, _body: &[u8]) -> Result<Vec<u8>, GatewayError> {
        *self.forwards.lock().unwrap() += 1;
        Ok(b"ok".to_vec())
    }
}

fn alice() -> Identity {
    Identity {
        subject: "CN=alice,OU=client,O=Org1".into(),
        spki_sha256: "a".repeat(64),
        issuer: "CN=ca-org1".into(),
    }
}

#[tokio::test]
async fn allow_forwards_and_audits_allow() {
    let audit = MockAudit::default();
    let upstream = MockUpstream::default();
    let policy = MockPolicy {
        decision: Decision { allow: true, reason: "allowed by rule".into(), policy_version: "/orders@v1".into() },
        calls: Arc::new(Mutex::new(vec![])),
    };

    let enforcer = Enforcer::new(policy, audit.clone(), upstream.clone());
    let out = enforcer.handle(&alice(), "GET", "/orders", b"body").await.unwrap();

    assert!(matches!(out, Outcome::Allowed(_)));
    assert_eq!(*upstream.forwards.lock().unwrap(), 1, "allow forwards to upstream");

    let recs = audit.records.lock().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[0].policy_version, "/orders@v1");
    assert_eq!(recs[0].who, "CN=alice,OU=client,O=Org1");
}

#[tokio::test]
async fn deny_is_refused_at_the_edge_and_audited() {
    let audit = MockAudit::default();
    let upstream = MockUpstream::default();
    let policy = MockPolicy {
        decision: Decision { allow: false, reason: "no matching rule".into(), policy_version: "/orders@v0".into() },
        calls: Arc::new(Mutex::new(vec![])),
    };

    let enforcer = Enforcer::new(policy, audit.clone(), upstream.clone());
    let out = enforcer.handle(&alice(), "DELETE", "/orders", b"body").await.unwrap();

    assert!(matches!(out, Outcome::Denied(_)));
    // Deny must never touch the upstream.
    assert_eq!(*upstream.forwards.lock().unwrap(), 0, "deny does not forward");

    let recs = audit.records.lock().unwrap();
    assert_eq!(recs.len(), 1, "deny is still audited");
    assert_eq!(recs[0].decision, "deny");
}
