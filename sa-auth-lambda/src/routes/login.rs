use lambda_http::http::{header, StatusCode};
use lambda_http::{Context, Request, Response};

use papo_provider_core::OAuthProvider;

use crate::context::AppContext;
use crate::Error;

pub fn login_handler(
    _: Request,
    _: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, Error> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(
            header::LOCATION,
            app_ctx
                .google_oauth_provider()
                .get_login_url(&app_ctx.cfg.google_oauth_config.redirect_url),
        )
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
    async fn login_handler_returns_well_formed_301() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        env::set_var("REDIRECT_URL", "https://solvastro.com/auth/callback");
        let cfg = AppConfig::new();
        let app_ctx = AppContext::new(cfg).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/login").unwrap();
        let ctx = Context::default();

        let result = login_handler(req, ctx, &app_ctx).unwrap();
        assert_eq!(result.status(), StatusCode::FOUND);
        assert_eq!(result.headers().get("location").unwrap(), "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fsolvastro.com%2Fauth%2Fcallback&prompt=consent&response_type=code&client_id=TEST_CLIENT_ID&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline");
    }
}