// repo: gateway/src/config.rs
use std::env;
use std::net::SocketAddr;

// All values come from the environment. Paths point at placeholder or
// test-network-generated material only. Never bake a real key/token here.
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub upstream_url: String,

    // Fabric gateway peer endpoint and the channels/chaincodes we call.
    pub fabric_endpoint: String,
    pub policy_channel: String,
    pub policy_chaincode: String,
    pub audit_channel: String,
    pub audit_chaincode: String,
    pub msp_id: String,

    // mTLS material. Server presents cert/key; ca_path is the org trust root
    // used to REQUIRE and verify client certs (same root Fabric CA issues from).
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,

    // Bound on the ledger call so a hung peer becomes a deny, not a hang.
    pub ledger_timeout_ms: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| env::var(k).map_err(|_| format!("missing env {k}"));
        let get_or = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());

        let listen = get_or("ZT_LISTEN", "0.0.0.0:8443")
            .parse()
            .map_err(|e| format!("bad ZT_LISTEN: {e}"))?;

        Ok(Config {
            listen,
            upstream_url: get_or("ZT_UPSTREAM_URL", "http://upstream.internal:8080"),
            fabric_endpoint: get_or("ZT_FABRIC_ENDPOINT", "peer0.org1.example.com:7051"),
            policy_channel: get_or("ZT_POLICY_CHANNEL", "policychannel"),
            policy_chaincode: get_or("ZT_POLICY_CHAINCODE", "policy"),
            audit_channel: get_or("ZT_AUDIT_CHANNEL", "auditchannel"),
            audit_chaincode: get_or("ZT_AUDIT_CHAINCODE", "audit"),
            msp_id: get_or("ZT_MSP_ID", "Org1MSP"),

            // Placeholder paths. Real files are mounted at deploy time.
            cert_path: get("ZT_TLS_CERT")?,
            key_path: get("ZT_TLS_KEY")?,
            ca_path: get("ZT_TLS_CA")?,

            ledger_timeout_ms: get_or("ZT_LEDGER_TIMEOUT_MS", "2000")
                .parse()
                .map_err(|e| format!("bad ZT_LEDGER_TIMEOUT_MS: {e}"))?,
        })
    }
}
