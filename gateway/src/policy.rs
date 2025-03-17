// repo: gateway/src/policy.rs
use crate::identity::Identity;
use serde::{Deserialize, Serialize};

// A decision names the exact policy version it used so an audit entry is
// reproducible against ledger state.
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

// Context passed to the chaincode Evaluate call alongside identity + action.
#[derive(Clone, Debug, Serialize)]
pub struct EvalContext {
    pub method: String,
    pub path: String,
}

// Fabric policy chaincode client. Evaluate(identity, action, context) queries
// the ledger. The gateway holds no authority of its own; the ledger decides.
// Revocation takes effect on the NEXT request because we query live state,
// never a cached grant.
pub trait PolicyClient {
    fn evaluate(&self, id: &Identity, action: &str, ctx: &EvalContext) -> Decision;
}

// Real-shaped Fabric gateway client. Submits an Evaluate query to the policy
// chaincode on the policy channel and parses the returned Decision JSON.
pub struct FabricPolicyClient {
    pub endpoint: String,
    pub channel: String,
    pub chaincode: String,
    pub msp_id: String,
}

impl PolicyClient for FabricPolicyClient {
    fn evaluate(&self, id: &Identity, action: &str, ctx: &EvalContext) -> Decision {
        // Shape of a real Fabric gateway query: connect to the peer, target
        // channel/chaincode, invoke "Evaluate" with args, decode result.
        let args = vec![
            id.key(),
            action.to_string(),
            serde_json::to_string(ctx).unwrap_or_default(),
        ];
        let raw = fabric_query(&self.endpoint, &self.channel, &self.chaincode, "Evaluate", &args);
        match raw {
            Ok(bytes) => serde_json::from_slice::<Decision>(&bytes)
                .unwrap_or_else(|_| Decision::deny("undecodable ledger response")),
            Err(e) => Decision::deny(&format!("ledger error: {e}")),
        }
    }
}

// Placeholder for the Fabric gateway SDK submit/evaluate call.
fn fabric_query(
    _endpoint: &str,
    _channel: &str,
    _chaincode: &str,
    _fn_name: &str,
    _args: &[String],
) -> Result<Vec<u8>, String> {
    Err("not wired to a peer in this build".to_string())
}
