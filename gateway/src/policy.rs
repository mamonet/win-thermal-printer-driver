// repo: gateway/src/policy.rs
use crate::identity::Identity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    pub reason: String,
    pub policy_version: String,
}

impl Decision {
    pub fn deny(reason: &str) -> Decision {
        Decision {
            allow: false,
            reason: reason.to_string(),
            policy_version: "unknown".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EvalContext {
    pub method: String,
    pub path: String,
}

// Typed errors around the ledger call so callers can distinguish a clean
// deny from a transport failure. Both still resolve to deny (see .final).
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("ledger transport: {0}")]
    Transport(String),
    #[error("ledger call timed out")]
    Timeout,
    #[error("undecodable ledger response")]
    Decode,
}

pub trait PolicyClient {
    fn evaluate(&self, id: &Identity, action: &str, ctx: &EvalContext) -> Decision;
}

pub struct FabricPolicyClient {
    pub endpoint: String,
    pub channel: String,
    pub chaincode: String,
    pub msp_id: String,
    pub timeout: Duration,
}

impl FabricPolicyClient {
    // Inner call returns a typed Result. The trait method below collapses it.
    fn try_evaluate(
        &self,
        id: &Identity,
        action: &str,
        ctx: &EvalContext,
    ) -> Result<Decision, PolicyError> {
        let args = vec![
            id.key(),
            action.to_string(),
            serde_json::to_string(ctx).map_err(|_| PolicyError::Decode)?,
        ];
        let bytes = fabric_query(
            &self.endpoint,
            &self.channel,
            &self.chaincode,
            "Evaluate",
            &args,
            self.timeout,
        )?;
        serde_json::from_slice::<Decision>(&bytes).map_err(|_| PolicyError::Decode)
    }
}

impl PolicyClient for FabricPolicyClient {
    fn evaluate(&self, id: &Identity, action: &str, ctx: &EvalContext) -> Decision {
        match self.try_evaluate(id, action, ctx) {
            Ok(d) => d,
            Err(e) => Decision::deny(&format!("ledger error: {e}")),
        }
    }
}

// Placeholder for the Fabric gateway SDK evaluate call with a timeout applied.
fn fabric_query(
    _endpoint: &str,
    _channel: &str,
    _chaincode: &str,
    _fn_name: &str,
    _args: &[String],
    _timeout: Duration,
) -> Result<Vec<u8>, PolicyError> {
    Err(PolicyError::Transport("not wired to a peer in this build".into()))
}
