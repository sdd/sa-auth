use std::env;
use cookie::Cookie;
use lambda_http::{Context, Request, Response};
use lambda_http::http::{header, StatusCode};

use crate::context::AppContext;
use crate::{AUTH_COOKIE_NAME, AUTH_COOKIE_DOMAIN, AUTH_COOKIE_PATH};
use crate::Error;

pub fn logout_handler(_: Request, _: Context, _: &AppContext) -> Result<Response<String>, Error> {
    let cookie = Cookie::build(AUTH_COOKIE_NAME, "")
        .domain(AUTH_COOKIE_DOMAIN)
        .path(AUTH_COOKIE_PATH)
        .http_only(true)
        .finish();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie.to_string())
        .body("".to_string())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use lambda_http::http::Uri;

    use crate::config::AppConfig;
    use crate::context::AppContext;
    use super::*;

    #[tokio::test]
    async fn logout_handler_returns_response_that_clears_auth_cookie() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = AppConfig::new();
        let app_ctx = AppContext::new(cfg).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/logout").unwrap();
        let ctx = Context::default();

        let result = logout_handler(req, ctx, &app_ctx).unwrap();
        println!("result: {:?}", &result);
        assert_eq!(result.status(), StatusCode::OK);

        let expected = format!("{}=; HttpOnly; Path={}; Domain={}", AUTH_COOKIE_NAME, AUTH_COOKIE_PATH, AUTH_COOKIE_DOMAIN);
        assert_eq!(result.headers().get(header::SET_COOKIE).unwrap(), &expected);
    }
}