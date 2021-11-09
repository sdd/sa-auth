use cookie::Cookie;
use lambda_http::http::{header, StatusCode};
use lambda_http::{Context, Request, Response};

use crate::context::AppContext;
use crate::Error;

pub fn logout_handler(
    _: Request,
    _: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, Error> {
    let cookie = Cookie::build(&app_ctx.cfg.auth_cookie_name, "")
        .domain(&app_ctx.cfg.auth_cookie_domain)
        .path(&app_ctx.cfg.auth_cookie_path)
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
    use lambda_http::http::Uri;
    use std::env;
    use std::str::FromStr;

    use super::*;
    use crate::config::AppConfig;
    use crate::context::AppContext;

    #[tokio::test]
    async fn logout_handler_returns_response_that_clears_auth_cookie() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        env::set_var("AUTH_COOKIE_DOMAIN", "localhost");
        env::set_var("AUTH_COOKIE_NAME", "auth");
        env::set_var("AUTH_COOKIE_PATH", "/");
        let cfg = AppConfig::new();
        let app_ctx = AppContext::new(cfg).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/logout").unwrap();
        let ctx = Context::default();

        let result = logout_handler(req, ctx, &app_ctx).unwrap();
        println!("result: {:?}", &result);
        assert_eq!(result.status(), StatusCode::OK);

        let expected = format!(
            "{}=; HttpOnly; Path={}; Domain={}",
            &app_ctx.cfg.auth_cookie_name,
            &app_ctx.cfg.auth_cookie_path,
            &app_ctx.cfg.auth_cookie_domain
        );
        assert_eq!(result.headers().get(header::SET_COOKIE).unwrap(), &expected);
    }
}
