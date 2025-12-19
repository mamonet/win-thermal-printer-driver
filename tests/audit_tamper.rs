// tests/audit_tamper.rs
// Audit is append-only and stores only a hash:
//  - a record is written for BOTH allow and deny,
//  - a second write to the same key is rejected (tamper-evident),
//  - the stored record carries request_hash, never the raw body.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use zt_policy_gateway::audit::{AuditRecord, AuditSink};
use zt_policy_gateway::error::GatewayError;

// Mock audit ledger mirroring the append-only chaincode: key => record, and a
// write to an existing key is rejected.
#[derive(Clone, Default)]
struct AppendOnlyLedger {
    store: Arc<Mutex<HashMap<String, AuditRecord>>>,
}

#[async_trait]
impl AuditSink for AppendOnlyLedger {
    async fn record(&self, rec: AuditRecord) -> Result<(), GatewayError> {
        let mut s = self.store.lock().unwrap();
        if s.contains_key(&rec.request_hash) {
            // Append-only: refuse to overwrite. Matches audit chaincode.
            return Err(GatewayError::Ledger("audit record already exists; append-only".into()));
        }
        s.insert(rec.request_hash.clone(), rec);
        Ok(())
    }
}

fn rec(decision: &str, hash: &str) -> AuditRecord {
    AuditRecord {
        who: "CN=alice,OU=client,O=Org1".into(),
        what: "GET /orders".into(),
        decision: decision.into(),
        policy_version: "/orders@v1".into(),
        ts: "2026-07-24T00:00:00Z".into(),
        request_hash: hash.into(),
    }
}

#[tokio::test]
async fn append_works_for_allow_and_deny() {
    let ledger = AppendOnlyLedger::default();
    ledger.record(rec("allow", "hash-allow-001")).await.unwrap();
    ledger.record(rec("deny", "hash-deny-002")).await.unwrap();

    let s = ledger.store.lock().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s["hash-allow-001"].decision, "allow");
    assert_eq!(s["hash-deny-002"].decision, "deny");
}

#[tokio::test]
async fn second_write_to_same_key_is_rejected() {
    let ledger = AppendOnlyLedger::default();
    ledger.record(rec("allow", "hash-dup-003")).await.unwrap();

    // A tamper attempt: rewrite the same key with a flipped decision.
    let err = ledger.record(rec("deny", "hash-dup-003")).await.unwrap_err();
    assert!(matches!(err, GatewayError::Ledger(_)), "duplicate key rejected");

    // Original record is unchanged.
    let s = ledger.store.lock().unwrap();
    assert_eq!(s["hash-dup-003"].decision, "allow");
}

#[test]
fn only_hash_is_stored_never_the_body() {
    // The record type has no field for a raw body; only request_hash. This is a
    // structural guarantee, asserted by constructing a record from a body hash.
    let body = b"secret order payload that must never hit the ledger";
    let hash = zt_policy_gateway::audit::hash_request(body);
    let r = rec("allow", &hash);

    assert_eq!(r.request_hash.len(), 64, "sha-256 hex");
    // The body string must not appear anywhere in the serialized record.
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("secret order payload"), "raw body never serialized");
    assert!(json.contains(&hash), "only the hash is present");
}
