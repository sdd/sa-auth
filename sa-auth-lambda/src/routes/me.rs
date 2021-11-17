use jsonwebtoken::{decode, DecodingKey, Validation};
use lambda_http::http::{header, StatusCode};
use lambda_http::{Context, Request, Response};
use serde_json;

use crate::context::AppContext;
use crate::Error;
use cookie::Cookie;
use sa_auth_model::Claims;

pub fn me_handler(
    req: Request,
    _: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, Error> {
    let cookies = req.headers().get_all(header::COOKIE);

    for cookie in cookies {
        if let Ok(cookie) = Cookie::parse(cookie.to_str().unwrap()) {
            if cookie.name() == &app_ctx.cfg.auth_cookie_name {
                if let Ok(token_data) = decode::<Claims>(
                    cookie.value(),
                    &DecodingKey::from_secret(app_ctx.cfg.jwt_secret.as_ref()),
                    &Validation::default(),
                ) {
                    let claims: Claims = token_data.claims;
                    let body = serde_json::to_string(&claims)?;

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Access-Control-Allow-Origin", "https://solvastro.com")
                        .header("Access-Control-Allow-Credentials", "true")
                        .body(body)
                        .unwrap());
                    // } else {
                    //     // Bad JWT for the cookie
                    //     println!("BAD JWT: {}", cookie.value());
                }
                // } else {
                //     // this cookie has the wrong name
                //     println!("Different cookie name: {}", cookie.name());
            }
            // } else {
            //     // this cookie header doesn't parse properly
            //     println!("Malformed cookie header");
        }
    }

    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body("401 Not Authorized".to_string())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Uri;
    use std::env;
    use std::str::FromStr;

    use crate::config::AppConfig;
    use crate::context::AppContext;

    use super::*;
    use crate::routes::callback::create_jwt;
    use cookie::Cookie;
    use sa_auth_model::{Claims, Role};

    #[tokio::test]
    async fn me_handler_gives_json_of_jwt() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        env::set_var("AUTH_COOKIE_DOMAIN", "localhost");
        env::set_var("AUTH_COOKIE_NAME", "auth");
        env::set_var("AUTH_COOKIE_PATH", "/");

        let cfg = AppConfig::new();
        let app_ctx = AppContext::new(cfg).await;

        let uid = "userid-001";
        let role = Role::Admin;
        let jwt_secret = b"TEST_JWT_SECRET";
        let jwt = create_jwt(uid, &role, jwt_secret.as_ref()).unwrap();

        let cookie = Cookie::build("auth", jwt)
            .domain("test.local")
            .path("/")
            .http_only(true)
            .finish();

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/some-weird-path").unwrap();
        req.headers_mut()
            .insert("Cookie", cookie.to_string().parse().unwrap());
        let ctx = Context::default();

        let result = me_handler(req, ctx, &app_ctx);
        println!("result: {:?}", &result);

        let result: Claims = serde_json::from_str(result.unwrap().body()).unwrap();

        assert_eq!(&result.sub, &uid);
        assert_eq!(&result.role, "Admin");
    }
}
