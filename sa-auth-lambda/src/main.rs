mod config;
mod context;
mod error;
mod routes;

use log::{debug};
use lambda_http::{Context, handler, lambda_runtime::{self, Error as LambdaError}, Request, Response};
use lambda_http::lambda_runtime::Error;

use crate::config::AppConfig;
use crate::context::AppContext;
use crate::routes::{callback, login, logout, me, not_found};

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    simple_logger::init_with_env().unwrap();
    
    let cfg = AppConfig::new();
    debug!("cfg: {:?}", &cfg);
    let app_ctx = AppContext::new(cfg).await;
    debug!("ctx: {:?}", &app_ctx);

    lambda_runtime::run(handler(|req, ctx| auth_handler(req, ctx, &app_ctx))).await?;
    Ok(())
}

async fn auth_handler(
    req: Request,
    ctx: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, LambdaError> {
    debug!("req: {:?}", &req);
    match req.uri().path() {
        "/auth/login" => login::login_handler(req, ctx, app_ctx),
        "/auth/logout" => logout::logout_handler(req, ctx, app_ctx),
        "/auth/callback" => callback::callback_handler(req, ctx, app_ctx).await,
        "/auth/me" => me::me_handler(req, ctx, app_ctx),
        _ => not_found::not_found_handler(req, ctx, app_ctx),
    }
}
