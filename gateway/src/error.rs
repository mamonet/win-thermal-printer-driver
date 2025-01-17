// repo: gateway/src/error.rs
use thiserror::Error;

// Every variant that is not an explicit allow must resolve to DENY upstream.
// Fail closed: an error is never an opening. The mapping lives in `is_deny`
// so no call site can accidentally treat a failure as permission.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("no client certificate presented")]
    NoClientCert,

    #[error("could not parse client identity: {0}")]
    IdentityParse(String),

    #[error("policy ledger unreachable: {0}")]
    LedgerUnreachable(String),

    #[error("denied by policy: {0}")]
    Denied(String),

    #[error("upstream error: {0}")]
    Upstream(String),
}

impl GatewayError {
    // There is no allow path through an error. This exists to make the
    // invariant explicit and greppable: all errors are denials.
    pub fn is_deny(&self) -> bool {
        true
    }

    // Human-facing reason recorded in the audit trail on refusal.
    pub fn deny_reason(&self) -> String {
        self.to_string()
    }
}
