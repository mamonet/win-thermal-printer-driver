// repo: gateway/src/audit.rs
use crate::identity::Identity;
use crate::policy::Decision;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

// One immutable audit record, appended to the audit channel as a Fabric tx.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub who: String,       // identity key (SPKI fp)
    pub subject: String,   // DN, for human reading only
    pub action: String,    // method + path
    pub allow: bool,
    pub reason: String,
    pub policy_version: String,
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

// Build the record from a decision that was allowed.
pub fn record_allow(id: &Identity, action: &str, d: &Decision) -> AuditRecord {
    AuditRecord {
        who: id.key(),
        subject: id.subject.clone(),
        action: action.to_string(),
        allow: d.allow,
        reason: d.reason.clone(),
        policy_version: d.policy_version.clone(),
        ts: now(),
    }
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
