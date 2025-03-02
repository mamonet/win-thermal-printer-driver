// repo: gateway/src/tls.rs
use crate::config::Config;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

// rustls ServerConfig that REQUIRES client auth against the org trust root.
// A handshake without a client cert is rejected at the TLS layer, before any
// request logic runs. No cert -> no conversation. Fail closed starts here.
pub fn server_config(cfg: &Config) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_key(&cfg.key_path)?;
    let roots = load_roots(&cfg.ca_path)?;

    // AllowAnyAuthenticatedClient == verification against `roots` is mandatory.
    // There is no "optional" verifier here; an anonymous client cannot connect.
    let verifier = AllowAnyAuthenticatedClient::new(roots);

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls server config: {e}"))?;

    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, String> {
    let mut rd = BufReader::new(File::open(path).map_err(|e| format!("open {path}: {e}"))?);
    let certs = rustls_pemfile::certs(&mut rd).map_err(|e| format!("read certs {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certs in {path}"));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_key(path: &str) -> Result<PrivateKey, String> {
    let mut rd = BufReader::new(File::open(path).map_err(|e| format!("open {path}: {e}"))?);
    // Accept PKCS8 or RSA. Placeholder/test key only; never a committed real key.
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut rd)
        .map_err(|e| format!("read key {path}: {e}"))?;
    if keys.is_empty() {
        let mut rd2 = BufReader::new(File::open(path).map_err(|e| format!("open {path}: {e}"))?);
        keys = rustls_pemfile::rsa_private_keys(&mut rd2)
            .map_err(|e| format!("read rsa key {path}: {e}"))?;
    }
    keys.into_iter()
        .next()
        .map(PrivateKey)
        .ok_or_else(|| format!("no private key in {path}"))
}

fn load_roots(path: &str) -> Result<RootCertStore, String> {
    let mut rd = BufReader::new(File::open(path).map_err(|e| format!("open {path}: {e}"))?);
    let cas = rustls_pemfile::certs(&mut rd).map_err(|e| format!("read ca {path}: {e}"))?;
    if cas.is_empty() {
        return Err(format!("no CA certs in {path}"));
    }
    let mut store = RootCertStore::empty();
    for c in cas {
        store
            .add(&Certificate(c))
            .map_err(|e| format!("add ca cert: {e}"))?;
    }
    Ok(store)
}
