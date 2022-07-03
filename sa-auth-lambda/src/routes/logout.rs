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
    use crate::context;

    use super::*;
    use crate::context::AppContext;

    #[tokio::test]
    async fn logout_handler_returns_response_that_clears_auth_cookie() {
        context::setup_test_env();
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
