use cookie::Cookie;
use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Request, Response};

use crate::context::AppContext;
use crate::Error;

pub fn logout_handler(_: Request, app_ctx: &AppContext) -> Result<Response<Body>, Error> {
    let cookie = Cookie::build(&app_ctx.cfg.auth_cookie_name, "")
        .domain(&app_ctx.cfg.auth_cookie_domain)
        .path(&app_ctx.cfg.auth_cookie_path)
        .http_only(true)
        .finish();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie.to_string())
        .body("".into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::context::AppContext;

    #[tokio::test]
    async fn logout_handler_returns_response_that_clears_auth_cookie() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("PATREON_CLIENT_ID", "TEST_CLIENT_ID_P");
        env::set_var("PATREON_CLIENT_SECRET", "TEST_CLIENT_SECRET_P");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        env::set_var("REDIRECT_URL", "https://localhost/redir");
        env::set_var("SUCCESS_REDIRECT_URL", "https://localhost/");
        env::set_var("PATREON_REDIRECT_URL", "https://localhost/redir");
        env::set_var("AUTH_COOKIE_DOMAIN", "localhost");
        env::set_var("AUTH_COOKIE_NAME", "auth");
        env::set_var("AUTH_COOKIE_PATH", "/");
        env::set_var("TABLE_NAME_IDENTITIES", "sa-identities");
        env::set_var("TABLE_NAME_USERS", "sa-users");
        env::set_var("TABLE_NAME_PATREON_TOKENS", "sa-patreon-tokens");
        env::set_var("PATREON_SUPPORT_CAMPAIGN_ID", "TEST_CAMPAIGN_ID");
        let app_ctx = AppContext::new().await;

        let req = Request::default();

        let result = logout_handler(req, &app_ctx).unwrap();
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
