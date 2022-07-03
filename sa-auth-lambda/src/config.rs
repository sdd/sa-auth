use envconfig::Envconfig;

#[derive(Debug, Envconfig)]
pub struct GoogleOAuthConfig {
    #[envconfig(from = "GOOGLE_CLIENT_ID")]
    pub client_id: String,
    #[envconfig(from = "GOOGLE_CLIENT_SECRET")]
    pub client_secret: String,
    #[envconfig(from = "REDIRECT_URL")]
    pub redirect_url: String,
}

#[derive(Debug, Envconfig)]
pub struct PatreonOAuthConfig {
    #[envconfig(from = "PATREON_CLIENT_ID")]
    pub client_id: String,
    #[envconfig(from = "PATREON_CLIENT_SECRET")]
    pub client_secret: String,
    #[envconfig(from = "PATREON_REDIRECT_URL")]
    pub redirect_url: String,
}

#[derive(Debug, Envconfig)]
pub struct AppConfig {
    #[envconfig(nested = true)]
    pub google_oauth_config: GoogleOAuthConfig,
    #[envconfig(nested = true)]
    pub patreon_oauth_config: PatreonOAuthConfig,

    #[envconfig(from = "JWT_SECRET")]
    pub jwt_secret: String,
    #[envconfig(from = "SUCCESS_REDIRECT_URL")]
    pub success_redirect_url: String,

    #[envconfig(from = "AUTH_COOKIE_NAME")]
    pub auth_cookie_name: String,
    #[envconfig(from = "AUTH_COOKIE_PATH")]
    pub auth_cookie_path: String,
    #[envconfig(from = "AUTH_COOKIE_DOMAIN")]
    pub auth_cookie_domain: String,

    #[envconfig(from = "TABLE_NAME_USERS")]
    pub table_name_users: String,
    #[envconfig(from = "TABLE_NAME_IDENTITIES")]
    pub table_name_identities: String,
    #[envconfig(from = "TABLE_NAME_PATREON_TOKENS")]
    pub table_name_patreon_tokens: String,

    #[envconfig(from = "PATREON_SUPPORT_CAMPAIGN_ID")]
    pub patreon_support_campaign_id: String,
}
