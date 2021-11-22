use async_trait::async_trait;
use reqwest::Error as ReqwestError;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

#[derive(Serialize, Debug)]
pub struct TokenRequest<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub grant_type: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
    pub scope: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identity {
    pub name: String,
    pub picture: String,
    pub email: String,
    pub id: String,
    pub verified_email: bool,
}

#[derive(ThisError, Debug)]
pub enum PapoProviderError {
    #[error("request error")]
    RequestError(#[from] ReqwestError),
}

#[async_trait]
pub trait OAuthProvider {
    fn get_login_url(&self, redirect_url: &str) -> String;
    async fn get_token(&self, code: &str) -> Result<TokenResponse, PapoProviderError>;
    async fn get_identity<I: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<I, PapoProviderError>;
}
