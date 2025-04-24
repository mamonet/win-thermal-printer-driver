// repo: gateway/src/upstream.rs
use crate::error::GatewayError;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request, Response, Uri};

// Forwards an ALLOWED request to the configured upstream and returns its
// response. Only reached after a positive ledger decision and a successful
// audit write; nothing calls this on the deny path.
#[derive(Clone)]
pub struct Upstream {
    base: String,
    client: Client<HttpConnector, Body>,
}

impl Upstream {
    pub fn new(base: String) -> Upstream {
        Upstream {
            base,
            client: Client::builder().build_http(),
        }
    }

    pub async fn forward(&self, req: Request<Body>) -> Result<Response<Body>, GatewayError> {
        let (mut parts, body) = req.into_parts();

        // Rewrite the target onto the upstream base, keeping path + query.
        let pq = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let uri: Uri = format!("{}{}", self.base.trim_end_matches('/'), pq)
            .parse()
            .map_err(|e| GatewayError::Upstream(format!("bad upstream uri: {e}")))?;
        parts.uri = uri;

        let out = Request::from_parts(parts, body);
        self.client
            .request(out)
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))
    }
}
