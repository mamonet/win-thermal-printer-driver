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
    // FIX: an Err from the ledger was previously allowed to bubble up, and a
    // caller upstream treated the missing decision as inconclusive -> allow.
    // That inverts the invariant. Collapse EVERY Err and timeout to an
    // explicit DENY right here so no error ever leaves this function as
    // anything but a deny. Nothing above this call can turn a failure into an
    // allow because a failure is no longer representable as one.
    //
    // FAIL CLOSED: ledger unreachable, timeout, decode failure -> deny.
    // (Revocation is live ledger state, so a revoked identity denies on its
    // very next request; there is no cached grant to go stale.)
    fn evaluate(&self, id: &Identity, action: &str, ctx: &EvalContext) -> Decision {
        match self.try_evaluate(id, action, ctx) {
            Ok(d) => d,
            Err(PolicyError::Timeout) => Decision::deny("ledger unreachable"),
            Err(e) => {
                // Any transport/decode error is a deny, full stop.
                Decision::deny(&format!("ledger unreachable: {e}"))
            }
        }
    }
}

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
