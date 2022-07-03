#![feature(async_closure)]

mod config;
mod context;
mod error;
mod routes;

use lambda_http::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE};
use lambda_http::http::{HeaderValue, Method};
use lambda_http::{service_fn, tower::ServiceBuilder, Body, Error, Request, Response};
use tower_http::cors::CorsLayer;
use tracing::debug;

use crate::context::AppContext;
use crate::routes::{authorize_patreon, callback, login, logout, me, not_found, patreon_callback};

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();

    let app_ctx = AppContext::new().await;
    debug!("ctx: {:?}", &app_ctx);
    let app_ctx_ref = &app_ctx;

    let cors_layer = CorsLayer::new()
        .allow_credentials(true)
        .allow_headers([ACCEPT, AUTHORIZATION, COOKIE, CONTENT_TYPE])
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_origin(
            format!("https://{}", &app_ctx.cfg.auth_cookie_domain)
                .parse::<HeaderValue>()
                .unwrap(),
        );

    let handler =
        ServiceBuilder::new()
            .layer(cors_layer)
            .service(service_fn(async move |req: Request| {
                auth_handler(req, app_ctx_ref).await
            }));

    lambda_http::run(handler).await?;
    Ok(())
}

async fn auth_handler(req: Request, app_ctx: &AppContext) -> Result<Response<Body>, Error> {
    debug!("req: {:?}, path: {:?}", &req, req.uri().path());
    match req.uri().path() {
        "/prod/auth/login" => login::login_handler(req, app_ctx),
        "/prod/auth/logout" => logout::logout_handler(req, app_ctx),
        "/prod/auth/callback" => callback::callback_handler(req, app_ctx).await,
        "/prod/auth/authorize/patreon" => authorize_patreon::login_patreon_handler(req, app_ctx),
        "/prod/auth/authorize/patreon/callback" => {
            patreon_callback::patreon_callback_handler(req, app_ctx).await
        }
        "/prod/auth/me" => me::me_handler(req, app_ctx),
        _ => not_found::not_found_handler(req, app_ctx),
    }
}

fn init_logging() {
    if atty::is(atty::Stream::Stdout) {
        // Running in a TTY: give the log output a glow-up
        tracing_subscriber::fmt()
            .pretty()
            .without_time()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing_subscriber::filter::LevelFilter::WARN.into()),
            )
            .init();
    } else {
        // Not in a TTY: JSON formatting suitable for sending to CloudWatch Logs
        tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing_subscriber::filter::LevelFilter::WARN.into()),
            )
            .init();
    }
}
