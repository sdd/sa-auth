use std::{env,fmt};
use log::debug;

use aws_sdk_dynamodb::{Client as DynamodbClient, Client, Error as DynamoDbError, SdkError};
use aws_sdk_dynamodb::error::{GetItemError, PutItemError};
use aws_sdk_dynamodb::model::AttributeValue;
use chrono::Utc;
use cookie::Cookie;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lambda_http::{handler, lambda_runtime::{self, Error as LambdaError}, Request, Context, Response, IntoResponse, RequestExt};
use lambda_http::http::{header,StatusCode};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize,Serialize};
use thiserror::Error as ThisError;
use unique_id::Generator;
use unique_id::string::StringGenerator;
use urlencoding;

const REDIRECT_URI: &'static str = "https://solvastro.com/auth/callback";
const DEFAULT_DEST_URL: &'static str = "https://solvastro.com";

const AUTH_COOKIE_DOMAIN: &'static str = "solvastro.com";
const AUTH_COOKIE_NAME: &'static str = "auth";
const AUTH_COOKIE_PATH: &'static str = "/";

const GOOGLE_OAUTH_URL_TEMPLATE: &'static str = "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={}&prompt=consent&response_type=code&client_id={}&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline";
const GOOGLE_ENDPOINT_TOKEN: &'static str = "https://oauth2.googleapis.com/token";
const GOOGLE_ENDPOINT_IDENTITY: &'static str = "https://www.googleapis.com/userinfo/v2/me";
const GOOGLE_IDENTITY_PREFIX: &'static str = "GOOG";

const DYNAMODB_TABLE_IDENTITIES: &'static str = "solvastro-identities";
const DYNAMODB_TABLE_USERS: &'static str = "solvastro-users";

#[derive(ThisError, Debug)]
pub enum AuthServiceError {
    #[error("no user found with user_id from identifier")]
    IdentityMissingUserId,
    #[error("unknown data store error")]
    IdentityUserNotFound,

    #[error("general dynamodb error")]
    DynamoDbError(#[from] DynamoDbError),

    #[error("could not get item from dynamodb")]
    DynamoDbGetItemError(#[from] SdkError<GetItemError>),

    #[error("could not put item into dynamodb")]
    DynamoDbPutItemError(#[from] SdkError<PutItemError>),

    #[error("could not create JWT")]
    JWTCreationError,
}

#[derive(Serialize, Debug)]
struct TokenRequest<'a> {
    code: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    redirect_uri: &'a str,
    grant_type: &'a str,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    token_type: String,
    scope: String,
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
struct GoogleIdentity {
    name: String,
    picture: String,
    email: String,
    id: String,
    verified_email: bool
}

#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn from_str(role: &str) -> Role {
        match role {
            "Admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

struct User {
    id: String,
    name: String,
    email: String,
    role: Role,
}

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    lambda_runtime::run(handler(auth_handler)).await?;
    Ok(())
}

async fn auth_handler(
    request: Request,
    _: Context
) -> Result<impl IntoResponse, LambdaError> {

    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID env var");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET env var");

    // TODO: should be in a common init, shared between auth_handler instantiations
    let (oauth_uri, client, dynamodb, id_generator) = init().await;

    let path = request.uri().path();
    match path {
        "/auth/login" => {
            Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, &oauth_uri)
                .body("".to_string())
                .unwrap())
        },

        "/auth/callback" => {
            let code: String = request.query_string_parameters().get("code").unwrap().into();
            let token_request = TokenRequest {
                code: &code,
                client_id: client_id.as_str(),
                client_secret: client_secret.as_str(),
                redirect_uri: REDIRECT_URI,
                grant_type: "authorization_code"
            };

            let token_response: TokenResponse = client
                .post(GOOGLE_ENDPOINT_TOKEN)
                .form(&token_request)
                .send()
                .await?
                .json::<TokenResponse>()
                .await?;

            println!("Token Response: {:?}", &token_response);

            // hit the identity endpoint with token_response.access_token as a Bearer token.
            let identity: GoogleIdentity = client
                .get(GOOGLE_ENDPOINT_IDENTITY)
                .bearer_auth(&token_response.access_token)
                .send()
                .await?
                .json::<GoogleIdentity>()
                .await?;

            let user: User = get_user(dynamodb, id_generator, identity).await?;

            let jwt = create_jwt(&user.id, &user.role)?;

            // set a cookie containing the JWT
            let cookie = Cookie::build(AUTH_COOKIE_NAME, jwt)
                .domain(AUTH_COOKIE_DOMAIN)
                .path(AUTH_COOKIE_PATH)
                .http_only(true)
                .finish();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Set-Cookie", cookie.to_string())
                .body(token_response.access_token)
                .unwrap())
        },

        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("404 Not Found".to_string())
                .unwrap())
        }
    }
}

async fn get_user(dynamodb: Client, id_generator: StringGenerator, identity: GoogleIdentity) -> Result<User, AuthServiceError> {
    // check to see if there is a corresponding entry in the identities table
    if let Some(matching_identity) = dynamodb.get_item()
        .table_name(DYNAMODB_TABLE_IDENTITIES)
        .key("id", AttributeValue::S(format!("{}:{}", GOOGLE_IDENTITY_PREFIX, identity.id)))
        .send()
        .await?.item {

        // if there is, retrieve the matching user from the users table.
        if let Some(user_id) = matching_identity.get("user_id") {
            if let Some(user) = dynamodb.get_item()
                .table_name(DYNAMODB_TABLE_USERS)
                .key("id", AttributeValue::S(format!("{}:{:?}", GOOGLE_IDENTITY_PREFIX, user_id)))
                .send()
                .await?.item {
                Ok(User {
                    id: user.get("id").unwrap().as_s().unwrap().clone(),
                    name: user.get("name").unwrap().as_s().unwrap().clone(),
                    email: user.get("email").unwrap().as_s().unwrap().clone(),
                    role: Role::from_str(user.get("role").unwrap().as_s().unwrap()),
                })
            } else {
                Err(AuthServiceError::IdentityUserNotFound)
            }
        } else {
            Err(AuthServiceError::IdentityMissingUserId)
        }
    } else {
        // If not, need to insert a new identity.

        // Check for a user with a matching email
        let user: Option<User> = if let Some(user) = dynamodb.get_item()
            .table_name(DYNAMODB_TABLE_USERS)
            .key("email", AttributeValue::S(identity.email.clone()))
            .send()
            .await?.item {
            Some(User {
                id: user.get("id").unwrap().as_s().unwrap().clone(),
                name: user.get("name").unwrap().as_s().unwrap().clone(),
                email: user.get("email").unwrap().as_s().unwrap().clone(),
                role: Role::from_str(user.get("role").unwrap().as_s().unwrap()),
            })
        } else {
            None
        };

        if let Some(user) = user {
            Ok(user)
        } else {
            // if there isn't, create a new user entry.
            let user = User {
                id: id_generator.next_id(),
                name: identity.name.clone(),
                email: identity.email.clone(),
                role: Role::User
            };

            // insert the new user
            dynamodb.put_item()
                .table_name(DYNAMODB_TABLE_USERS)
                .item("id", AttributeValue::S(String::from(&user.id)))
                .item("name", AttributeValue::S(String::from(&user.name)))
                .item("email", AttributeValue::S(String::from(&user.email)))
                .send()
                .await?;

            // insert the new identity
            dynamodb.put_item()
                .table_name(DYNAMODB_TABLE_IDENTITIES)
                .item("id", AttributeValue::S(format!("{}:{}", GOOGLE_IDENTITY_PREFIX, identity.id)))
                .item("user_id", AttributeValue::S(String::from(&user.id)))
                .send()
                .await?;

            Ok(user)
        }
    }
}

fn create_jwt(uid: &str, role: &Role) -> Result<String, AuthServiceError> {
    let jwt_secret = env::var("JWT_SECRET").expect("Missing JWT_SECRET env var");

    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(3600))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS512);

    encode(&header, &claims, &EncodingKey::from_secret(jwt_secret.as_ref()))
        .map_err(|_| AuthServiceError::JWTCreationError)
}

async fn init() -> (String, ReqwestClient, DynamodbClient, StringGenerator) {
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID env var");

    let oauth_uri = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={}&prompt=consent&response_type=code&client_id={}&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline",
        urlencoding::encode(REDIRECT_URI),
        client_id
    );

    let client = reqwest::Client::new();

    let shared_config = aws_config::load_from_env().await;
    let dynamodb = DynamodbClient::new(&shared_config);

    let id_generator = StringGenerator::default();
    (oauth_uri, client, dynamodb, id_generator)
}