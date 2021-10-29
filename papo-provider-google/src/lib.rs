use async_trait::async_trait;
use reqwest::Client as ReqwestClient;

use papo_provider_core::{Identity,OAuthProvider,TokenRequest,TokenResponse,PapoProviderError};

pub const GOOGLE_ENDPOINT_TOKEN: &'static str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_ENDPOINT_IDENTITY: &'static str = "https://www.googleapis.com/userinfo/v2/me";
pub const GOOGLE_IDENTITY_PREFIX: &'static str = "GOOG";

pub struct GoogleOAuthProvider<'a> {
    reqwest_client: &'a ReqwestClient,
    client_id: &'a str,
    client_secret: &'a str,
    token_url: &'a str,
    identity_url: &'a str,
    redirect_url: &'a str,
}

impl<'a> GoogleOAuthProvider<'a> {
    pub fn new(reqwest_client: &'a ReqwestClient, client_id: &'a str, client_secret: &'a str, redirect_url: &'a str) -> GoogleOAuthProvider<'a> {
        GoogleOAuthProvider {
            reqwest_client,
            client_id,
            client_secret,
            token_url: GOOGLE_ENDPOINT_TOKEN,
            identity_url: GOOGLE_ENDPOINT_IDENTITY,
            redirect_url,
        }
    }

    pub fn with_token_url(self, token_url: &'a str) -> Self {
        GoogleOAuthProvider {
            token_url,
            ..self
        }
    }

    pub fn with_identity_url(self, identity_url: &'a str) -> Self {
        GoogleOAuthProvider {
            identity_url,
            ..self
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleOAuthProvider<'_> {
    fn get_login_url(&self, redirect_url: &str) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={}&prompt=consent&response_type=code&client_id={}&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline",
            urlencoding::encode(redirect_url),
            self.client_id
        )
    }

    async fn get_token(&self, code: &str) -> Result<TokenResponse, PapoProviderError> {
        let token_request = TokenRequest {
            code,
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            redirect_uri: &self.redirect_url,
            grant_type: "authorization_code"
        };

        Ok(self.reqwest_client
            .post(self.token_url)
            .form(&token_request)
            .send()
            .await?
            .json::<TokenResponse>()
            .await?)
    }

    async fn get_identity(&self, token: &str) -> Result<Identity, PapoProviderError> {
        Ok(self.reqwest_client
            .get(self.identity_url)
            .bearer_auth(token)
            .send()
            .await?
            .json::<Identity>()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_google_oauth_provider_get_identity_works() {
        use wiremock::{MockServer, Mock, ResponseTemplate};
        use wiremock::matchers::{method, header, path};
        let mock_server = MockServer::start().await;

        let mock_identity = Identity {
            name: "TEST_GOOG_NAME".to_string(),
            picture: ":-)".to_string(),
            email: "TEST_GOOG_EMAIL".to_string(),
            id: "TEST_GOOG_ID".to_string(),
            verified_email: false
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
        let provider = GoogleOAuthProvider::new(
            &reqwest_client,
            client_id.into(),
            client_secret.into(),
            "REDIR_URL".into(),
        ).with_identity_url(&format!("{}/get-id", mock_server.uri()));


        let token = "TEST_TOKEN";
        let result = provider.get_identity(token).await.unwrap();

        assert_eq!(result.id, "TEST_GOOG_ID");
    }

    #[tokio::test]
    async fn test_google_oauth_provider_get_oauth_token_works() {
        use wiremock::{MockServer, Mock, ResponseTemplate};
        use wiremock::matchers::{method, path};
        let mock_server = MockServer::start().await;

        let _expected_body = TokenRequest{
            code: "TEST_CODE",
            client_id: "FAKE_ID",
            client_secret: "FAKE_SECRET",
            redirect_uri: "REDIR_URL",
            grant_type: "authorization_code"
        };

        let mock_token_response = TokenResponse{
            access_token: "A_TOKEN".to_string(),
            expires_in: 1000,
            token_type: "TEST".to_string(),
            scope: "TEST_SCOPE".to_string(),
            refresh_token: "R_TOKEN".to_string()
        };

        Mock::given(method("POST"))
            .and(path("/get-token"))
            // TODO
            //.and(body_string("code=TEST_CODE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_token_response))
            .mount(&mock_server)
            .await;

        let reqwest_client = ReqwestClient::default();
        let provider = GoogleOAuthProvider::new(
            &reqwest_client,
            "FAKE_ID".into(),
            "FAKE_SECRET".into(),
            "REDIR_URL".into(),
        ).with_token_url(&format!("{}/get-token", mock_server.uri()));

        let code = "TEST_CODE";
        let result = provider.get_token(code).await.unwrap();

        assert_eq!(result.access_token, "A_TOKEN");
    }
}
