use async_trait::async_trait;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::fmt;

use papo_provider_core::{OAuthProvider, PapoProviderError, TokenRequest, TokenResponse};

pub const PATREON_ENDPOINT_TOKEN: &'static str = "https://www.patreon.com/api/oauth2/token";
pub const PATREON_ENDPOINT_IDENTITY: &'static str = "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=created,email,full_name,thumb_url,is_email_verified&fields[memberships]=patron_status";
pub const PATREON_IDENTITY_PREFIX: &'static str = "PATREON";

// fields[user]=created,email,full_name,thumb_url,is_email_verified
// fields[memberships]=patron_status

#[derive(Debug)]
pub struct PatreonOAuthProvider<'a> {
    reqwest_client: &'a ReqwestClient,
    client_id: &'a str,
    client_secret: &'a str,
    token_url: &'a str,
    identity_url: &'a str,
    redirect_url: &'a str,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum PatronStatus {
    Active,
    Declined,
    Former,
}

impl fmt::Display for PatronStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatronStatus::Active => write!(f, "Active"),
            PatronStatus::Declined => write!(f, "Declined"),
            PatronStatus::Former => write!(f, "Former"),
        }
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PatreonIdentity {
    id: String,
    created: String,
    email: String,
    full_name: String,
    thumb_url: String,
    is_email_verified: bool,
    patron_status: PatronStatus,
}

impl<'a> PatreonOAuthProvider<'a> {
    pub fn new(
        reqwest_client: &'a ReqwestClient,
        client_id: &'a str,
        client_secret: &'a str,
        redirect_url: &'a str,
    ) -> PatreonOAuthProvider<'a> {
        PatreonOAuthProvider {
            reqwest_client,
            client_id,
            client_secret,
            token_url: PATREON_ENDPOINT_TOKEN,
            identity_url: PATREON_ENDPOINT_IDENTITY,
            redirect_url,
        }
    }

    pub fn with_token_url(self, token_url: &'a str) -> Self {
        PatreonOAuthProvider { token_url, ..self }
    }

    pub fn with_identity_url(self, identity_url: &'a str) -> Self {
        PatreonOAuthProvider {
            identity_url,
            ..self
        }
    }
}

#[async_trait]
impl OAuthProvider for PatreonOAuthProvider<'_> {
    fn get_login_url(&self, redirect_url: &str) -> String {
        let raw_scopes = ["identity", "identity[email]", "identity.memberships"].join(" ");

        let scope = urlencoding::encode(&raw_scopes);

        format!(
            "https://www.patreon.com/oauth2/authorize?redirect_uri={}&response_type=code&client_id={}&scope={}",
            &urlencoding::encode(redirect_url),
            &self.client_id,
            &scope
        )
    }

    async fn get_token(&self, code: &str) -> Result<TokenResponse, PapoProviderError> {
        let token_request = TokenRequest {
            code,
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            redirect_uri: &self.redirect_url,
            grant_type: "authorization_code",
        };

        Ok(self
            .reqwest_client
            .post(self.token_url)
            .form(&token_request)
            .send()
            .await?
            .json::<TokenResponse>()
            .await?)
    }

    async fn get_identity<I: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<I, PapoProviderError> {
        Ok(self
            .reqwest_client
            .get(self.identity_url)
            .bearer_auth(token)
            .send()
            .await?
            .json::<I>()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_patreon_oauth_provider_get_identity_works() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock_server = MockServer::start().await;

        let mock_identity = PatreonIdentity {
            full_name: "TEST_PATREON_NAME".to_string(),
            thumb_url: ":-)".to_string(),
            email: "TEST_PATREON_EMAIL".to_string(),
            id: "TEST_PATREON_ID".to_string(),
            is_email_verified: false,
            created: "2021-01-01T00:00:00.000Z".to_string(),
            patron_status: PatronStatus::Active,
        };

        Mock::given(method("GET"))
            .and(path("/get-id"))
            .and(header("Authorization", "Bearer TEST_TOKEN"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_identity))
            .mount(&mock_server)
            .await;

        let reqwest_client = ReqwestClient::default();

        let client_id = "FAKE_ID";
        let client_secret = "FAKE_SECRET";
        let identity_url = format!("{}/get-id", mock_server.uri());
        let provider = PatreonOAuthProvider::new(
            &reqwest_client,
            client_id.into(),
            client_secret.into(),
            "REDIR_URL".into(),
        )
        .with_identity_url(&identity_url);

        let token = "TEST_TOKEN";
        let result: PatreonIdentity = provider.get_identity(token).await.unwrap();

        assert_eq!(result.id, "TEST_PATREON_ID");
        assert_eq!(result.patron_status, PatronStatus::Active);
    }
}
