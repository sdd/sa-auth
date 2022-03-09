use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use log::trace;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::fmt;

use papo_provider_core::{OAuthProvider, PapoProviderError, TokenRequest, TokenResponse};

pub const PATREON_ENDPOINT_TOKEN: &str = "https://www.patreon.com/api/oauth2/token";
pub const PATREON_ENDPOINT_IDENTITY: &str = "https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields%5Buser%5D=created,email,full_name,thumb_url,is_email_verified&fields%5Bmember%5D=patron_status";
pub const PATREON_IDENTITY_PREFIX: &str = "PATREON";

pub const PATREON_SA_CAMPAIGN_ID: &str = "";

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
    #[serde(alias = "active_patron")]
    Active,
    #[serde(alias = "declined_patron")]
    Declined,
    #[serde(alias = "former_patron")]
    Former,
}

impl PatronStatus {
    pub fn from_str(role: &str) -> PatronStatus {
        match role {
            "Active" => PatronStatus::Active,
            "active_patron" => PatronStatus::Active,
            "Former" => PatronStatus::Former,
            "former_patron" => PatronStatus::Former,
            "declined_patron" => PatronStatus::Declined,
            _ => PatronStatus::Declined,
        }
    }
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

#[derive(Debug, Serialize)]
pub struct PatreonToken {
    pub id: String,         // sa user id
    pub patreon_id: String, // patreon user id
    pub access_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub refresh_token: String,
    pub scope: String,
}

impl PatreonToken {
    pub fn from_token_response(resp: TokenResponse, patron_id: &str, user_id: &str) -> Self {
        PatreonToken {
            id: user_id.to_string(),
            patreon_id: patron_id.to_string(),
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            scope: resp.scope,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(resp.expires_in as i64),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PatreonIdentityResponse {
    pub data: PatreonIdentityResponseData,
    pub included: Vec<CampaignMembership>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PatreonIdentityResponseData {
    pub id: String,
    pub attributes: PatreonIdentityAttributes,
}

impl PatreonIdentityResponse {
    pub fn status_for_membership_id(&self, campaign_id: &str) -> PatronStatus {
        self.included
            .iter()
            .find(|&c| c.id.eq(campaign_id))
            .map_or(PatronStatus::Declined, |c| {
                c.attributes.patron_status.clone()
            })
    }

    pub fn best_patron_status(&self) -> PatronStatus {
        if self
            .included
            .iter()
            .any(|c| c.attributes.patron_status == PatronStatus::Active)
        {
            PatronStatus::Active
        } else if self
            .included
            .iter()
            .any(|c| c.attributes.patron_status == PatronStatus::Former)
        {
            PatronStatus::Former
        } else {
            PatronStatus::Declined
        }
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PatreonIdentityAttributes {
    pub created: DateTime<Utc>,
    pub email: String,
    pub full_name: String,
    pub is_email_verified: bool,
    pub thumb_url: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct CampaignMembership {
    pub id: String,
    pub attributes: CampaignMembershipAttributes,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct CampaignMembershipAttributes {
    pub patron_status: PatronStatus,
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
        let raw_scopes = [
            "identity",
            "identity[email]", /*, "identity.memberships"*/
        ]
        .join(" ");

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
            client_id: self.client_id,
            client_secret: self.client_secret,
            redirect_uri: self.redirect_url,
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

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, PapoProviderError> {
        Ok(self
            .reqwest_client
            .post(self.token_url)
            .query(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id),
                ("client_secret", self.client_secret),
            ])
            .send()
            .await?
            .json::<TokenResponse>()
            .await?)
    }

    async fn get_identity<I: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<I, PapoProviderError> {
        let response = self
            .reqwest_client
            .get(self.identity_url)
            .bearer_auth(token)
            .send()
            .await?;

        let text = response.text().await;
        trace!("patreon identity response: {:?}", &text);

        Ok(serde_json::from_str(&text?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_patreon_response_deserialization() {
        let raw_response = r#"{
  "data": {
    "attributes": {
      "created": "2022-01-06T09:46:51.000+00:00",
      "email": "TEST_EMAIL",
      "full_name": "Testy McTestFace",
      "is_email_verified": true,
      "thumb_url": "https://c8.patreon.com/2/200/TEST_ID"
    },
    "id": "TEST_ID",
    "relationships": {
      "memberships": {
        "data": [
          {
            "id": "TEST_MEMBERSHIP_ID",
            "type": "member"
          }
        ]
      }
    },
    "type": "user"
  },
  "included": [
    {
      "attributes": {
        "patron_status": "active_patron"
      },
      "id": "TEST_MEMBERSHIP_ID",
      "type": "member"
    }
  ],
  "links": {
    "self": "https://www.patreon.com/api/oauth2/v2/user/TEST_ID"
  }
}
        "#;

        let obj: PatreonIdentityResponse = serde_json::from_str(raw_response).unwrap();

        assert_eq!(obj.data.id, "TEST_ID");
        assert_eq!(obj.data.attributes.email, "TEST_EMAIL");
        assert_eq!(obj.included[0].id, "TEST_MEMBERSHIP_ID");
        assert_eq!(
            obj.included[0].attributes.patron_status,
            PatronStatus::Active
        );
    }

    #[tokio::test]
    async fn test_patreon_oauth_provider_get_identity_works() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock_server = MockServer::start().await;

        let mock_identity = PatreonIdentityResponse {
            data: PatreonIdentityResponseData {
                id: "TEST_PATREON_ID".to_string(),
                attributes: PatreonIdentityAttributes {
                    created: Utc.ymd(2022, 1, 5).and_hms_milli(17, 40, 0, 123),
                    email: "TEST_PATREON_EMAIL".to_string(),
                    full_name: "TEST_PATREON_NAME".to_string(),
                    is_email_verified: true,
                    thumb_url: "TEST_PATREON_THUMB_URL".to_string(),
                },
            },
            included: vec![
                CampaignMembership {
                    id: "ANOTHER_CAMPAIGN".to_string(),
                    attributes: CampaignMembershipAttributes {
                        patron_status: PatronStatus::Former,
                    },
                },
                CampaignMembership {
                    id: "OUR_CAMPAIGN".to_string(),
                    attributes: CampaignMembershipAttributes {
                        patron_status: PatronStatus::Active,
                    },
                },
            ],
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
        let result: PatreonIdentityResponse = provider.get_identity(token).await.unwrap();

        assert_eq!(result.data.id, "TEST_PATREON_ID");
        assert_eq!(
            result.status_for_membership_id("OUR_CAMPAIGN"),
            PatronStatus::Active
        );
        assert_eq!(result.best_patron_status(), PatronStatus::Active);
        assert_eq!(
            result.status_for_membership_id("ANOTHER_CAMPAIGN"),
            PatronStatus::Former
        );
        assert_eq!(
            result.status_for_membership_id("NON_EXISTENT_CAMPAIGN"),
            PatronStatus::Declined
        );
    }
}
