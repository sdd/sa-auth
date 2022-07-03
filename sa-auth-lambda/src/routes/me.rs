use jsonwebtoken::{decode, DecodingKey, Validation};
use lambda_http::http::StatusCode;
use lambda_http::{Body, Request, Response};
use tracing::{debug, info};

use crate::context::AppContext;
use crate::{Error, HeaderValue};
use cookie::Cookie;
use lambda_http::http::header::GetAll;
use sa_model::claims::Claims;

pub fn me_handler(req: Request, app_ctx: &AppContext) -> Result<Response<Body>, Error> {
    if let Some(claims) = get_claims_from_cookies(&req.headers().get_all("Cookie"), app_ctx) {
        let body = serde_json::to_string(&claims)?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(body.into())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("401 Not Authorized".into())
            .unwrap())
    }
}

pub fn get_claims_from_cookies(
    cookies: &GetAll<HeaderValue>,
    app_ctx: &AppContext,
) -> Option<Claims> {
    for cookie in cookies {
        if let Ok(cookie) = cookie.to_str() {
            if let Ok(cookie) = Cookie::parse(cookie) {
                if cookie.name() == app_ctx.cfg.auth_cookie_name {
                    if let Ok(token_data) = decode::<Claims>(
                        cookie.value(),
                        &DecodingKey::from_secret(app_ctx.cfg.jwt_secret.as_ref()),
                        &Validation::default(),
                    ) {
                        return Some(token_data.claims);
                    } else {
                        // Bad JWT for the cookie
                        info!("BAD JWT: {}", cookie.value());
                    }
                } else {
                    // this cookie has the wrong name
                    debug!("Different cookie name: {}", cookie.name());
                }
            } else {
                // this cookie header doesn't parse properly
                info!("Malformed cookie header");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;

    use crate::context::AppContext;

    use super::*;
    use crate::routes::callback::create_jwt;
    use cookie::Cookie;
    use lambda_http::http::Uri;
    use sa_model::{claims::Claims, role::Role};

    #[tokio::test]
    async fn me_handler_gives_json_of_jwt() {
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

        let uid = "userid-001";
        let role = Role::Admin;
        let jwt_secret = b"TEST_JWT_SECRET";
        let jwt = create_jwt(uid, &role, jwt_secret.as_ref(), false, false).unwrap();

        let cookie = Cookie::build("auth", jwt)
            .domain("test.local")
            .path("/")
            .http_only(true)
            .finish();

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/some-weird-path").unwrap();
        req.headers_mut()
            .insert("Cookie", cookie.to_string().parse().unwrap());

        let result = me_handler(req, &app_ctx).unwrap();
        println!("result: {:?}", &result);

        let result: Claims = serde_json::from_slice(result.into_body().as_ref()).unwrap();

        assert_eq!(&result.sub, &uid);
        assert_eq!(&result.role, "Admin");
    }
}
