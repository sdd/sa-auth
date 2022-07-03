use aws_sdk_dynamodb::Client as DynamodbClient;
use envconfig::Envconfig;
use papo_provider_google::GoogleOAuthProvider;
use papo_provider_patreon::PatreonOAuthProvider;
use reqwest::Client as ReqwestClient;
use sa_auth_model::{
    DynamoDbIdentityRepository, DynamoDbPatreonTokenRepository, DynamoDbUserRepository,
};
use unique_id::string::StringGenerator;

use crate::config::AppConfig;

#[derive(Debug)]
pub struct AppContext {
    pub cfg: AppConfig,
    pub id_generator: StringGenerator,

    dynamodb_client: DynamodbClient,
    reqwest_client: ReqwestClient,
}

impl AppContext {
    pub async fn new() -> AppContext {
        AppContext::with_config(
            AppConfig::init_from_env().expect("Could not instantiate AppConfig from env vars"),
        )
        .await
    }

    pub async fn with_config(cfg: AppConfig) -> AppContext {
        let id_generator = StringGenerator::default();
        let reqwest_client = ReqwestClient::new();

        let shared_config = aws_config::load_from_env().await;
        let dynamodb_client = DynamodbClient::new(&shared_config);

        AppContext {
            cfg,
            id_generator,
            reqwest_client,
            dynamodb_client,
        }
    }

    pub fn google_oauth_provider(&self) -> GoogleOAuthProvider {
        GoogleOAuthProvider::new(
            &self.reqwest_client,
            &self.cfg.google_oauth_config.client_id,
            &self.cfg.google_oauth_config.client_secret,
            &self.cfg.google_oauth_config.redirect_url,
        )
    }
    pub fn patreon_oauth_provider(&self) -> PatreonOAuthProvider {
        PatreonOAuthProvider::new(
            &self.reqwest_client,
            &self.cfg.patreon_oauth_config.client_id,
            &self.cfg.patreon_oauth_config.client_secret,
            &self.cfg.patreon_oauth_config.redirect_url,
        )
    }

    pub fn identity_repository(&self) -> DynamoDbIdentityRepository {
        DynamoDbIdentityRepository::new(
            &self.dynamodb_client,
            self.cfg.table_name_identities.to_owned(),
        )
    }

    pub fn user_repository(&self) -> DynamoDbUserRepository {
        DynamoDbUserRepository::new(&self.dynamodb_client, self.cfg.table_name_users.to_owned())
    }

    pub fn patreon_token_repository(&self) -> DynamoDbPatreonTokenRepository {
        DynamoDbPatreonTokenRepository::new(
            &self.dynamodb_client,
            self.cfg.table_name_patreon_tokens.to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use unique_id::Generator;

    #[tokio::test]
    async fn init_context_returns_a_working_context() {
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

        let app_ctx: AppContext = AppContext::new().await;

        let generated_id = app_ctx.id_generator.next_id();
        assert_ne!(generated_id, "");
    }
}
