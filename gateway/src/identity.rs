// repo: gateway/src/identity.rs
use crate::error::GatewayError;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

// Who is calling, extracted from the presented client cert after mTLS.
// No cert -> no conversation (enforced at the TLS layer; here we assume the
// verified DER leaf is in hand).
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub issuer: String,
    // SPKI SHA-256 fingerprint: hash of the SubjectPublicKeyInfo.
    // This is the STABLE identity anchor. A subject DN can be renamed or
    // reissued (CN=alice today, reassigned tomorrow) and is therefore
    // spoofable as an identity key; the public key the holder actually
    // controls is what we bind policy to. Rekey == new identity, on purpose.
    pub spki_sha256: String,
}

impl Identity {
    pub fn from_der(der: &[u8]) -> Result<Identity, GatewayError> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| GatewayError::IdentityParse(e.to_string()))?;

        // Hash the raw SubjectPublicKeyInfo bytes, not the DN.
        let spki = cert.public_key().raw;
        let mut h = Sha256::new();
        h.update(spki);
        let spki_sha256 = hex(&h.finalize());

        Ok(Identity {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            spki_sha256,
        })
    }

    // Policy is keyed on the SPKI fingerprint, never the DN alone.
    pub fn key(&self) -> String {
        self.spki_sha256.clone()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
