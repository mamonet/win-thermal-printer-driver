// repo: gateway/src/audit.rs
use crate::identity::Identity;
use crate::policy::Decision;
use sha2::{Digest, Sha256};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

// One immutable audit record, appended to the audit channel as a Fabric tx.
// The raw request body NEVER leaves the process. We store only its SHA-256,
// which is enough to prove which body a decision applied to without ever
// putting request contents on the ledger.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub who: String,       // identity key (SPKI fp)
    pub subject: String,   // DN, human reading only
    pub action: String,    // method + path
    pub allow: bool,
    pub reason: String,
    pub policy_version: String,
    pub body_sha256: String, // hash of the body, never the body itself
    pub ts: u64,
}

pub trait AuditSink {
    fn record(&self, rec: &AuditRecord) -> Result<(), String>;
}

pub struct FabricAuditSink {
    pub endpoint: String,
    pub channel: String,
    pub chaincode: String,
    pub msp_id: String,
}

impl AuditSink for FabricAuditSink {
    fn record(&self, rec: &AuditRecord) -> Result<(), String> {
        let payload = serde_json::to_string(rec).map_err(|e| e.to_string())?;
        fabric_submit(&self.endpoint, &self.channel, &self.chaincode, "Record", &[payload])
    }
}

// FIX: earlier the record was built (and the body hashed) only on allow, so
// denials left no trail. Record BOTH allow and deny: this single builder is
// used for every outcome. `d.allow` carries which way it went. The audit
// trail must be complete or it proves nothing.
pub fn build_record(id: &Identity, action: &str, body: &[u8], d: &Decision) -> AuditRecord {
    AuditRecord {
        who: id.key(),
        subject: id.subject.clone(),
        action: action.to_string(),
        allow: d.allow,
        reason: d.reason.clone(),
        policy_version: d.policy_version.clone(),
        body_sha256: sha256_hex(body), // hash only, raw body never recorded
        ts: now(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn fabric_submit(
    _endpoint: &str,
    _channel: &str,
    _chaincode: &str,
    _fn_name: &str,
    _args: &[String],
) -> Result<(), String> {
    Err("not wired to a peer in this build".to_string())
}
