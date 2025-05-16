// repo: gateway/src/main.rs
mod audit;
mod config;
mod enforce;
mod error;
mod identity;
mod policy;
mod tls;
mod upstream;

use audit::FabricAuditSink;
use config::Config;
use enforce::Enforcer;
use error::GatewayError;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use identity::Identity;
use policy::FabricPolicyClient;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use upstream::Upstream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env().map_err(|e| format!("config: {e}"))?;

    // mTLS acceptor: client cert REQUIRED. No cert -> handshake rejected.
    let tls_config = tls::server_config(&cfg)?;
    let acceptor = TlsAcceptor::from(tls_config);

    let policy = Arc::new(FabricPolicyClient {
        endpoint: cfg.fabric_endpoint.clone(),
        channel: cfg.policy_channel.clone(),
        chaincode: cfg.policy_chaincode.clone(),
        msp_id: cfg.msp_id.clone(),
        timeout: Duration::from_millis(cfg.ledger_timeout_ms),
    });
    let audit = Arc::new(FabricAuditSink {
        endpoint: cfg.fabric_endpoint.clone(),
        channel: cfg.audit_channel.clone(),
        chaincode: cfg.audit_chaincode.clone(),
        msp_id: cfg.msp_id.clone(),
    });
    let enforcer = Enforcer {
        policy,
        audit,
        upstream: Upstream::new(cfg.upstream_url.clone()),
    };

    let listener = TcpListener::bind(cfg.listen).await?;
    println!("gateway listening on {} (mTLS required)", cfg.listen);

    // Graceful shutdown on ctrl-c: stop accepting, let in-flight finish.
    let mut shutdown = Box::pin(signal::ctrl_c());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                println!("shutdown signal, draining");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { eprintln!("accept error: {e}"); continue; }
                };
                let acceptor = acceptor.clone();
                let enforcer = enforcer.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(acceptor, enforcer, stream).await {
                        eprintln!("conn {peer} error: {e}");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn serve_conn(
    acceptor: TlsAcceptor,
    enforcer: Enforcer,
    stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Handshake. Fails if the client presents no cert (required client auth).
    let tls = acceptor.accept(stream).await?;

    // Pull the verified client identity from the TLS session. Absence of a
    // peer cert here is impossible given required auth, but we still fail
    // closed if it is somehow missing. Fail closed everywhere.
    let identity = match peer_identity(&tls) {
        Ok(id) => id,
        Err(_) => {
            // Serve a single 403 and drop the connection.
            let svc = service_fn(|_req: Request<Body>| async {
                Ok::<_, hyper::Error>(forbidden("no verified client identity"))
            });
            Http::new().serve_connection(tls, svc).await?;
            return Ok(());
        }
    };

    let svc = service_fn(move |req: Request<Body>| {
        let enforcer = enforcer.clone();
        let identity = identity.clone();
        async move { Ok::<_, hyper::Error>(enforcer.handle(identity, req).await) }
    });

    Http::new().serve_connection(tls, svc).await?;
    Ok(())
}

// Extract identity from the negotiated TLS connection's peer certificates.
fn peer_identity(
    tls: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Result<Identity, GatewayError> {
    let (_, session) = tls.get_ref();
    let certs = session.peer_certificates().ok_or(GatewayError::NoClientCert)?;
    let leaf = certs.first().ok_or(GatewayError::NoClientCert)?;
    Identity::from_der(&leaf.0)
}

fn forbidden(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(format!("denied: {reason}")))
        .unwrap()
}
