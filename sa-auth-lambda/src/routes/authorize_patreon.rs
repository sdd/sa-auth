use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Request, Response};
use papo_provider_core::OAuthProvider;

use crate::context::AppContext;
use crate::Error;

pub fn login_patreon_handler(_: Request, app_ctx: &AppContext) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(
            header::LOCATION,
            app_ctx
                .patreon_oauth_provider()
                .get_login_url(&app_ctx.cfg.patreon_oauth_config.redirect_url),
        )
        .body("".into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use crate::context;
    use lambda_http::http::Uri;
    use std::str::FromStr;

    use super::*;
    use crate::context::AppContext;

    #[tokio::test]
    async fn login_handler_returns_well_formed_301() {
        context::setup_test_env();
        let app_ctx = AppContext::new().await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/login").unwrap();

        let result = login_patreon_handler(req, &app_ctx).unwrap();
        assert_eq!(result.status(), StatusCode::FOUND);
        assert_eq!(result.headers().get("location").unwrap(), "https://www.patreon.com/oauth2/authorize?redirect_uri=https%3A%2F%2Flocalhost%2Fredir&response_type=code&client_id=TEST_CLIENT_ID_P&scope=identity%20identity%5Bemail%5D");
    }
}
