use std::env;
use aws_sdk_dynamodb::{Client as DynamodbClient};
use lambda_http::{Context, Request, Response};
use lambda_http::http::{StatusCode};
use reqwest::Client as ReqwestClient;

use crate::context::AppContext;
use crate::Error;

pub fn not_found_handler(_: Request, _: Context, _: &AppContext) -> Result<Response<String>, Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("404 Not Found".to_string())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use lambda_http::http::Uri;

    use crate::config::init_config;
    use crate::context::init_context;
    use crate::routes::not_found::not_found_handler;

    use super::*;

    #[tokio::test]
    async fn not_found_handler_gives_404() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = init_config().await;
        let shared_config = aws_config::load_from_env().await;
        let dynamodb_client = DynamodbClient::new(&shared_config);
        let reqwest_client = ReqwestClient::new();

        let app_ctx: AppContext = init_context(cfg, &dynamodb_client, &reqwest_client).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/some-weird-path").unwrap();
        let ctx = Context::default();

        let result = not_found_handler(req, ctx, &app_ctx).unwrap();
        assert_eq!(result.status(), 404);
    }
}