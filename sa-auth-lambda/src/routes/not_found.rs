use lambda_http::http::StatusCode;
use lambda_http::{Context, Request, Response};

use crate::context::AppContext;
use crate::Error;

pub fn not_found_handler(
    _: Request,
    _: Context,
    _: &AppContext,
) -> Result<Response<String>, Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("404 Not Found".to_string())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Uri;
    use std::env;
    use std::str::FromStr;

    use crate::config::AppConfig;
    use crate::context::AppContext;
    use crate::routes::not_found::not_found_handler;

    use super::*;

    #[tokio::test]
    async fn not_found_handler_gives_404() {
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
        let cfg = AppConfig::new();
        let app_ctx = AppContext::new(cfg).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/some-weird-path").unwrap();
        let ctx = Context::default();

        let result = not_found_handler(req, ctx, &app_ctx).unwrap();
        assert_eq!(result.status(), 404);
    }
}
