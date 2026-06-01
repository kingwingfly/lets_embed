#![cfg_attr(
    feature = "validate-jwt",
    feature(iterator_try_collect, duration_constructors)
)]

#[cfg(feature = "validate-jwt")]
mod jwt;

use async_trait::async_trait;
use pingora::prelude::*;
use tracing_subscriber::EnvFilter;

const ADDR: &str = "0.0.0.0:8080";

struct Ingress {
    upstream: HttpPeer,
    #[cfg(feature = "validate-jwt")]
    policy_aud: String,
}

#[async_trait]
impl ProxyHttp for Ingress {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(self.upstream.clone()))
    }

    #[cfg(feature = "validate-jwt")]
    #[tracing::instrument(skip_all)]
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let Some(jwt) = session
            .get_header("Cf-Access-Jwt-Assertion")
            .map(|value| value.as_bytes())
        else {
            tracing::info!(reason = "no token", "reject");
            return Ok(true);
        };

        jwt::verify(jwt, &self.policy_aud)
            .map_err(|e| Error::because(ErrorType::HTTPStatus(403), "forbidden", e))?;

        Ok(false)
    }

    #[tracing::instrument(skip_all)]
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let content_type = upstream_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            });

        let Some(content_type) = content_type else {
            return Ok(());
        };

        let cache_control = match content_type.as_str() {
            t if t.starts_with("image/") => Some("public, max-age=31536000, immutable"), // 1 year

            "text/html"
            | "text/css"
            | "application/javascript"
            | "text/javascript"
            | "application/wasm" => Some("public, max-age=2592000"), // 30 days

            _ => None,
        };

        if let Some(value) = cache_control {
            upstream_response.insert_header(http::header::CACHE_CONTROL, value)?;
        }

        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway=info,pingora=info".parse().unwrap()),
        )
        .init();

    #[cfg(feature = "validate-jwt")]
    if jwt::keys().is_none() {
        tracing::error!("Failed to get pub keys");
        return;
    }

    #[cfg(feature = "validate-jwt")]
    let Ok(policy_aud) = std::env::var("POLICY_AUD") else {
        tracing::error!(env_var = "POLICY_AUD", "Not presented");
        return;
    };

    let mut my_server = Server::new(None).unwrap();

    my_server.bootstrap();

    let mut ingress = http_proxy_service(
        &my_server.configuration,
        Ingress {
            upstream: HttpPeer::new("127.0.0.1:3000", false, "".to_string()),
            #[cfg(feature = "validate-jwt")]
            policy_aud,
        },
    );
    ingress.add_tcp(ADDR);
    my_server.add_service(ingress);

    tracing::info!("listening on {ADDR}");
    my_server.run_forever();
}
