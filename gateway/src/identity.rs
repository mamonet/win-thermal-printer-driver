// repo: gateway/src/identity.rs
use crate::error::GatewayError;
use x509_parser::prelude::*;

// Who is calling, extracted from the presented client cert after mTLS.
// No cert -> no conversation (handled at the TLS layer; here we assume the
// verified DER leaf is in hand).
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub issuer: String,
}

impl Identity {
    // Parse subject + issuer DN from the DER-encoded leaf certificate.
    pub fn from_der(der: &[u8]) -> Result<Identity, GatewayError> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| GatewayError::IdentityParse(e.to_string()))?;

        Ok(Identity {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
        })
    }

    // Stable key used for policy lookups.
    pub fn key(&self) -> String {
        self.subject.clone()
    }
}
