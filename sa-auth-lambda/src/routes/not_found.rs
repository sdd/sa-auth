use lambda_http::http::StatusCode;
use lambda_http::{Body, Request, Response};

use crate::context::AppContext;
use crate::Error;

pub fn not_found_handler(_: Request, _: &AppContext) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("404 Not Found".into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use crate::context;

    use crate::context::AppContext;
    use crate::routes::not_found::not_found_handler;

    use super::*;

    #[tokio::test]
    async fn not_found_handler_gives_404() {
        context::setup_test_env();
        let app_ctx = AppContext::new().await;

        let req = Request::default();

        let result = not_found_handler(req, &app_ctx).unwrap();
        assert_eq!(result.status(), 404);
    }
}
