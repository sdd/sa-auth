use aws_sdk_dynamodb::Client as DynamodbClient;
use reqwest::Client as ReqwestClient;
use unique_id::string::StringGenerator;
use papo_provider_google::GoogleOAuthProvider;
use sa_auth_model::{DynamoDbIdentityRepository, DynamoDbUserRepository};

use crate::config::AppConfig;
use crate::REDIRECT_URI;

#[derive(Debug)]
pub struct AppContext {
    pub cfg: AppConfig,
    pub id_generator: StringGenerator,

    dynamodb_client: DynamodbClient,
    reqwest_client: ReqwestClient,
}

impl AppContext {
    pub async fn new(cfg: AppConfig) -> AppContext {
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
        GoogleOAuthProvider::new(&self.reqwest_client, &self.cfg.google_oauth_config.client_id, &self.cfg.google_oauth_config.client_secret, REDIRECT_URI)
    }

    pub fn identity_repository(&self) -> DynamoDbIdentityRepository {
        DynamoDbIdentityRepository::new(&self.dynamodb_client)
    }

    pub fn user_repository(&self) -> DynamoDbUserRepository {
        DynamoDbUserRepository::new(&self.dynamodb_client)
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use unique_id::Generator;
    use crate::config::AppConfig;
    use super::*;

    #[tokio::test]
    async fn init_context_returns_a_working_context() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = AppConfig::new();
        let app_ctx: AppContext = AppContext::new(cfg).await;

        let generated_id = app_ctx.id_generator.next_id();
        assert_ne!(generated_id, "");
    }
}
