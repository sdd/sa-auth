mod config;
mod context;
mod error;
mod routes;

use lambda_http::http::StatusCode;
use lambda_http::lambda_runtime::Error;
use lambda_http::{
    handler,
    lambda_runtime::{self, Error as LambdaError},
    Context, Request, Response,
};
use log::debug;

use crate::config::AppConfig;
use crate::context::AppContext;
use crate::routes::{authorize_patreon, callback, login, logout, me, not_found};

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
    if req.method() == lambda_http::http::method::Method::OPTIONS {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Credentials", "true")
            .header(
                "Access-Control-Allow-Origin",
                format!("https://{}", &app_ctx.cfg.auth_cookie_domain),
            )
            .header(
                "Access-Control-Allow-Headers",
                "Accept,Authorization,Cookie,Content-Type",
            )
            .header(
                "Access-Control-Allow-Methods",
                "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
            )
            .body("".to_string())
            .unwrap())
    } else {
        match req.uri().path() {
            "/auth/login" => login::login_handler(req, ctx, app_ctx),
            "/auth/logout" => logout::logout_handler(req, ctx, app_ctx),
            "/auth/callback" => callback::callback_handler(req, ctx, app_ctx).await,
            "/auth/authorize/patreon" => authorize_patreon::login_patreon_handler(req, ctx, app_ctx),
            "/auth/me" => me::me_handler(req, ctx, app_ctx),
            _ => not_found::not_found_handler(req, ctx, app_ctx),
        }
    }
}
