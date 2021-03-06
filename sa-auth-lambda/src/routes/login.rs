use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Request, Response};
use papo_provider_core::OAuthProvider;

use crate::context::AppContext;
use crate::Error;

pub fn login_handler(_: Request, app_ctx: &AppContext) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(
            header::LOCATION,
            app_ctx
                .google_oauth_provider()
                .get_login_url(&app_ctx.cfg.google_oauth_config.redirect_url),
        )
        .body("".into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use crate::context;

    use super::*;
    use crate::context::AppContext;

    #[tokio::test]
    async fn login_handler_returns_well_formed_301() {
        context::setup_test_env();
        let app_ctx = AppContext::new().await;

        let req = Request::default();

        let result = login_handler(req, &app_ctx).unwrap();
        assert_eq!(result.status(), StatusCode::FOUND);
        assert_eq!(result.headers().get("location").unwrap(), "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Flocalhost%2Fredir&prompt=consent&response_type=code&client_id=TEST_CLIENT_ID&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline");
    }
}
