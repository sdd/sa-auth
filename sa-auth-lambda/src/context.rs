use std::env;

use aws_sdk_dynamodb::Client as DynamodbClient;
use reqwest::Client as ReqwestClient;
use unique_id::Generator;
use unique_id::string::StringGenerator;
use papo_provider_google::GoogleOAuthProvider;
use sa_auth_model::{DynamoDbIdentityRepository, DynamoDbUserRepository};

use crate::config::AppConfig;
use crate::REDIRECT_URI;

pub struct AppContext<'a> {
    pub cfg: AppConfig,
    pub id_generator: StringGenerator,
    pub identity_repository: DynamoDbIdentityRepository<'a>,
    pub user_repository: DynamoDbUserRepository<'a>,
    pub google_oauth_provider: GoogleOAuthProvider<'a>,
}

pub async fn init_context<'a>(cfg: AppConfig, dynamodb_client: &'a DynamodbClient, reqwest_client: &'a ReqwestClient) -> AppContext<'a> {
    let id_generator = StringGenerator::default();

    let google_oauth_provider = GoogleOAuthProvider::new(reqwest_client, cfg.google_oauth_config.client_id.clone(), cfg.google_oauth_config.client_secret.clone(), REDIRECT_URI.into());
    let identity_repository = DynamoDbIdentityRepository::new(dynamodb_client);
    let user_repository = DynamoDbUserRepository::new(dynamodb_client);

    AppContext {
        cfg,
        id_generator,
        identity_repository,
        user_repository,
        google_oauth_provider,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::init_config;
    use crate::context::init_context;
    use super::*;

    #[tokio::test]
    async fn init_context_returns_a_working_context() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = init_config().await;
        let shared_config = aws_config::load_from_env().await;
        let dynamodb_client = DynamodbClient::new(&shared_config);
        let reqwest_client = ReqwestClient::new();

        let app_ctx: AppContext = init_context(cfg, &dynamodb_client, &reqwest_client).await;

        let generated_id = app_ctx.id_generator.next_id();
        assert_ne!(generated_id, "");
    }
}
