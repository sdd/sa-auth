mod config;
mod context;
mod error;
mod routes;

use aws_sdk_dynamodb::{Client as DynamodbClient};
use lambda_http::{Context, handler, lambda_runtime::{self, Error as LambdaError}, Request, Response};
use lambda_http::lambda_runtime::Error;
use reqwest::Client as ReqwestClient;

use config::AppConfig;
use context::AppContext;
use routes::{callback, login, not_found};

const REDIRECT_URI: &'static str = "https://solvastro.com/auth/callback";
const AUTH_COOKIE_DOMAIN: &'static str = "solvastro.com";
const AUTH_COOKIE_NAME: &'static str = "auth";
const AUTH_COOKIE_PATH: &'static str = "/";

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    let cfg: AppConfig = config::init_config().await;
    let aws_config = aws_config::load_from_env().await;
    let dynamodb_client = DynamodbClient::new(&aws_config);
    let reqwest_client = ReqwestClient::new();

    let app_ctx: AppContext = context::init_context(cfg, &dynamodb_client, &reqwest_client).await;

    lambda_runtime::run(handler(|req, ctx| auth_handler(req, ctx, &app_ctx))).await?;
    Ok(())
}

async fn auth_handler(
    request: Request,
    ctx: Context,
    app_ctx: &AppContext<'_>,
) -> Result<Response<String>, LambdaError> {
    match request.uri().path() {
        "/auth/login" => login::login_handler(request, ctx, app_ctx),
        "/auth/callback" => callback::callback_handler(request, ctx, app_ctx).await,
        _ => not_found::not_found_handler(request, ctx, app_ctx),
    }
}
