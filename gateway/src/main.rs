#![feature(iterator_try_collect, duration_constructors)]

mod jwt;

use std::env;

use jwt::verify;

use async_trait::async_trait;
use pingora::prelude::*;
use tracing_subscriber::EnvFilter;

use crate::jwt::keys;

struct Ingress {
    upstream: HttpPeer,
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

    #[tracing::instrument(skip_all)]
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        if !session.req_header().uri.path().starts_with("/admin") {
            return Ok(false);
        }
        let Some(jwt) = session
            .get_header("Cf-Access-Jwt-Assertion")
            .map(|value| value.as_bytes())
        else {
            tracing::info!(reason = "no token", "reject");
            return Ok(true);
        };

        verify(jwt, &self.policy_aud)
            .map_err(|e| Error::because(ErrorType::HTTPStatus(403), "forbidden", e))?;

        Ok(false)
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway=info,pingora=info".parse().unwrap()),
        )
        .init();

    if keys().is_none() {
        tracing::error!("Failed to get pub keys");
        return;
    }

    let Ok(policy_aud) = env::var("POLICY_AUD") else {
        tracing::error!(env_var = "POLICY_AUD", "Not presented");
        return;
    };

    let mut my_server = Server::new(None).unwrap();

    my_server.bootstrap();

    let mut ingress = http_proxy_service(
        &my_server.configuration,
        Ingress {
            upstream: HttpPeer::new("127.0.0.1:3000", false, "".to_string()),
            policy_aud,
        },
    );
    ingress.add_tcp("127.0.0.1:8080");
    my_server.add_service(ingress);

    my_server.run_forever();
}
