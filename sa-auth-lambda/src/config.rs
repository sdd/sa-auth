use std::env;

use crate::REDIRECT_URI;

#[derive(Debug)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug)]
pub struct AppConfig {
    pub google_oauth_config: GoogleOAuthConfig,
    pub jwt_secret: String,
}

pub async fn init_config() -> AppConfig {
    let jwt_secret = env::var("JWT_SECRET").expect("Missing JWT_SECRET env var");
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID env var");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET env var");

    let google_oauth_config = GoogleOAuthConfig {
        client_id,
        client_secret,
        redirect_url: REDIRECT_URI.into(),
    };

    AppConfig {
        google_oauth_config,
        jwt_secret,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::init_config;
    use super::*;

    #[tokio::test]
    async fn init_config_returns_a_working_config() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let result = init_config().await;

        assert_eq!(result.google_oauth_config.client_id, "TEST_CLIENT_ID");
        assert_eq!(result.google_oauth_config.client_secret, "TEST_CLIENT_SECRET");
        assert_eq!(result.jwt_secret, "TEST_JWT_SECRET");
    }
}
