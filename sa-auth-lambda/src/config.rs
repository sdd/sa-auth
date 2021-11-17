use std::env;

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
    pub success_redirect_url: String,

    pub auth_cookie_name: String,
    pub auth_cookie_path: String,
    pub auth_cookie_domain: String,

    pub table_name_users: String,
    pub table_name_identities: String,
}

impl AppConfig {
    pub fn new() -> AppConfig {
        let jwt_secret = env::var("JWT_SECRET").expect("Missing JWT_SECRET env var");
        let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID env var");
        let client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET env var");
        let redirect_url = env::var("REDIRECT_URL").expect("Missing REDIRECT_URL env var");
        let success_redirect_url =
            env::var("SUCCESS_REDIRECT_URL").expect("Missing SUCCESS_REDIRECT_URL env var");

        let auth_cookie_name =
            env::var("AUTH_COOKIE_NAME").expect("Missing AUTH_COOKIE_NAME env var");
        let auth_cookie_path =
            env::var("AUTH_COOKIE_PATH").expect("Missing AUTH_COOKIE_PATH env var");
        let auth_cookie_domain =
            env::var("AUTH_COOKIE_DOMAIN").expect("Missing AUTH_COOKIE_DOMAIN env var");

        let table_name_identities =
            env::var("TABLE_NAME_IDENTITIES").expect("Missing TABLE_NAME_IDENTITIES env var");
        let table_name_users =
            env::var("TABLE_NAME_USERS").expect("Missing TABLE_NAME_USERS env var");

        let google_oauth_config = GoogleOAuthConfig {
            client_id,
            client_secret,
            redirect_url,
        };

        AppConfig {
            google_oauth_config,
            jwt_secret,
            auth_cookie_domain,
            auth_cookie_name,
            auth_cookie_path,
            success_redirect_url,

            table_name_identities,
            table_name_users,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_config_returns_a_working_config() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        env::set_var("REDIRECT_URL", "https://localhost/redir");
        env::set_var("SUCCESS_REDIRECT_URL", "https://localhost/");
        env::set_var("AUTH_COOKIE_DOMAIN", "localhost");
        env::set_var("AUTH_COOKIE_NAME", "auth");
        env::set_var("AUTH_COOKIE_PATH", "/");
        env::set_var("TABLE_NAME_IDENTITIES", "sa-identities");
        env::set_var("TABLE_NAME_USERS", "sa-users");

        let result = AppConfig::new();

        assert_eq!(result.google_oauth_config.client_id, "TEST_CLIENT_ID");
        assert_eq!(
            result.google_oauth_config.client_secret,
            "TEST_CLIENT_SECRET"
        );
        assert_eq!(result.jwt_secret, "TEST_JWT_SECRET");
        assert_eq!(
            result.google_oauth_config.redirect_url,
            "https://localhost/redir"
        );
    }
}
