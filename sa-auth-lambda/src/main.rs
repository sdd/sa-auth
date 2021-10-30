#![feature(no_coverage)]
mod config;
mod context;
mod error;
mod routes;

use lambda_http::{Context, handler, lambda_runtime::{self, Error as LambdaError}, Request, Response};
use lambda_http::lambda_runtime::Error;

use crate::config::AppConfig;
use crate::context::AppContext;
use crate::routes::{callback, login, logout, me, not_found};

#[no_coverage]
#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    let cfg = AppConfig::new();
    let app_ctx = AppContext::new(cfg).await;

    lambda_runtime::run(handler(|req, ctx| auth_handler(req, ctx, &app_ctx))).await?;
    Ok(())
}

async fn auth_handler(
    request: Request,
    ctx: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, LambdaError> {
    match request.uri().path() {
        "/auth/login" => login::login_handler(request, ctx, app_ctx),
        "/auth/logout" => logout::logout_handler(request, ctx, app_ctx),
        "/auth/callback" => callback::callback_handler(request, ctx, app_ctx).await,
        "/auth/me" => me::me_handler(request, ctx, app_ctx),
        _ => not_found::not_found_handler(request, ctx, app_ctx),
    }
}
