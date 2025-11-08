// tests/fail_closed.rs
// Fail closed at every point the gateway meets the ledger:
//  - policy ledger unreachable/errors => DENY, never allow.
//  - audit write fails => DENY (a decision we cannot prove, we do not permit).
// In neither case is the upstream reached.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use zt_policy_gateway::audit::{AuditRecord, AuditSink};
use zt_policy_gateway::enforce::{Enforcer, Outcome};
use zt_policy_gateway::error::GatewayError;
use zt_policy_gateway::identity::Identity;
use zt_policy_gateway::policy::{Decision, PolicyClient};
use zt_policy_gateway::upstream::Upstream;

// Policy client that always errors (peer down, timeout, TLS failure...).
struct UnreachablePolicy;

#[async_trait]
impl PolicyClient for UnreachablePolicy {
    async fn evaluate(&self, _id: &Identity, _action: &str, _ctx: &str) -> Result<Decision, GatewayError> {
        Err(GatewayError::Ledger("peer unreachable".into()))
    }
}

// Policy client that allows, used to isolate the audit-failure path.
struct AllowPolicy;

#[async_trait]
impl PolicyClient for AllowPolicy {
    async fn evaluate(&self, _id: &Identity, _action: &str, _ctx: &str) -> Result<Decision, GatewayError> {
        Ok(Decision { allow: true, reason: "allowed by rule".into(), policy_version: "/orders@v1".into() })
    }
}

// Audit sink that always fails to commit.
struct FailingAudit;

#[async_trait]
impl AuditSink for FailingAudit {
    async fn record(&self, _rec: AuditRecord) -> Result<(), GatewayError> {
        Err(GatewayError::Ledger("audit commit failed".into()))
    }
}

#[derive(Clone, Default)]
struct GuardUpstream {
    forwards: Arc<Mutex<u32>>,
}

#[async_trait]
impl Upstream for GuardUpstream {
    async fn forward(&self, _id: &Identity, _action: &str, _body: &[u8]) -> Result<Vec<u8>, GatewayError> {
        *self.forwards.lock().unwrap() += 1;
        Ok(b"ok".to_vec())
    }
}

#[derive(Default)]
struct NoopAudit;

#[async_trait]
impl AuditSink for NoopAudit {
    async fn record(&self, _rec: AuditRecord) -> Result<(), GatewayError> {
        Ok(())
    }
}

fn alice() -> Identity {
    Identity { subject: "CN=alice,OU=client,O=Org1".into(), spki_sha256: "c".repeat(64), issuer: "CN=ca-org1".into() }
}

#[tokio::test]
async fn ledger_unreachable_denies_never_allows() {
    let upstream = GuardUpstream::default();
    let enforcer = Enforcer::new(UnreachablePolicy, NoopAudit, upstream.clone());

    let out = enforcer.handle(&alice(), "GET", "/orders", b"x").await.unwrap();
    // Must be a deny; a ledger error is never surfaced as allow.
    assert!(matches!(out, Outcome::Denied(_)), "ledger error must deny");
    assert_eq!(*upstream.forwards.lock().unwrap(), 0, "no forward on ledger error");
}

#[tokio::test]
async fn audit_failure_denies() {
    let upstream = GuardUpstream::default();
    // Policy allows, but the audit write fails => we cannot prove the decision.
    let enforcer = Enforcer::new(AllowPolicy, FailingAudit, upstream.clone());

    let out = enforcer.handle(&alice(), "GET", "/orders", b"x").await.unwrap();
    assert!(matches!(out, Outcome::Denied(_)), "unprovable decision must deny");
    assert_eq!(*upstream.forwards.lock().unwrap(), 0, "no forward when audit fails");
}
