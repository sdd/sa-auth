use std::{env,fmt};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

use async_trait::async_trait;
use aws_sdk_dynamodb::{Client as DynamodbClient, Error as DynamoDbError, SdkError};
use aws_sdk_dynamodb::error::{GetItemError, PutItemError};
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::output::PutItemOutput;
use chrono::Utc;
use cookie::Cookie;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lambda_http::{handler, lambda_runtime::{self, Error as LambdaError}, Request, Context, Response, RequestExt};
use lambda_http::http::{header,StatusCode};
use lambda_http::lambda_runtime::Error;
use reqwest::Client as ReqwestClient;
use reqwest::Error as ReqwestError;
use serde::{Deserialize,Serialize};
use thiserror::Error as ThisError;
use unique_id::Generator;
use unique_id::string::StringGenerator;
use urlencoding;

const REDIRECT_URI: &'static str = "https://solvastro.com/auth/callback";
//const DEFAULT_DEST_URL: &'static str = "https://solvastro.com";

const AUTH_COOKIE_DOMAIN: &'static str = "solvastro.com";
const AUTH_COOKIE_NAME: &'static str = "auth";
const AUTH_COOKIE_PATH: &'static str = "/";

const DYNAMODB_TABLE_IDENTITIES: &'static str = "solvastro-identities";
const DYNAMODB_TABLE_USERS: &'static str = "solvastro-users";

#[derive(ThisError, Debug)]
pub enum UserParseError {
    #[error("Missing Id")]
    MissingId,
    #[error("Id not a string")]
    IdNotAString,
    #[error("Missing name")]
    MissingName,
    #[error("Name not a string")]
    NameNotAString,
    #[error("Missing email")]
    MissingEmail,
    #[error("Email not a string")]
    EmailNotAString,
    #[error("Missing role")]
    MissingRole,
    #[error("Role not a string")]
    RoleNotAString,
}

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

    #[error("item not returned in DynamoDb response")]
    MissingItemError,

    #[error("could not put item into dynamodb")]
    DynamoDbPutItemError(#[from] SdkError<PutItemError>),

    #[error("could not create JWT")]
    JWTCreationError,

    #[error("could not parse user from db")]
    DbUserParseError(#[from] UserParseError),

    #[error("request error")]
    RequestError(#[from] ReqwestError),
}

#[derive(Deserialize, Debug)]
pub struct Identity {
    id: String,
    user_id: String,
}

#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
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
pub struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(Debug)]
pub struct User {
    id: String,
    name: String,
    email: String,
    role: Role,
}

impl TryFrom<HashMap<String, AttributeValue>> for User {
    type Error = UserParseError;

    fn try_from(user: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        if let Some(id) = user.get("id") {
            if let Ok(id) = id.as_s() {
                if let Some(name) = user.get("name") {
                    if let Ok(name) = name.as_s() {
                        if let Some(email) = user.get("email") {
                            if let Ok(email) = email.as_s() {
                                if let Some(role) = user.get("role") {
                                    if let Ok(role) = role.as_s() {
                                        Ok(User {
                                            id: id.clone(),
                                            name: name.clone(),
                                            email: email.clone(),
                                            role: Role::from_str(role),
                                        })
                                    } else {
                                        Err(UserParseError::RoleNotAString)
                                    }
                                } else {
                                    Err(UserParseError::MissingRole)
                                }
                            } else {
                                Err(UserParseError::EmailNotAString)
                            }
                        } else {
                            Err(UserParseError::MissingEmail)
                        }
                    } else {
                        Err(UserParseError::NameNotAString)
                    }
                } else {
                    Err(UserParseError::MissingName)
                }
            } else {
                Err(UserParseError::IdNotAString)
            }
        } else {
            Err(UserParseError::MissingId)
        }
    }
}

#[derive(Debug)]
pub struct AppConfig {
    google_oauth_config: GoogleOAuthConfig,
    jwt_secret: String,
}

pub struct AppContext<'a> {
    cfg: AppConfig,
    id_generator: StringGenerator,
    identity_repository: DynamoDbIdentityRepository<'a>,
    user_repository: DynamoDbUserRepository<'a>,
    google_oauth_provider: GoogleOAuthProvider<'a>,
}

#[async_trait]
trait IdentityRepository {
    async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError>;
    async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>>;
}

#[async_trait]
trait UserRepository {
    async fn get_by_id(&self, id: &str) -> Result<Option<User>, AuthServiceError>;
    async fn get_by_email(&self, id: &str) -> Result<Option<User>, AuthServiceError>;
    async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>>;
}

struct DynamoDbIdentityRepository<'a> {
    client: &'a DynamodbClient,
    table_name: String,
}

impl <'a> DynamoDbIdentityRepository<'a> {
    pub fn new(client: &DynamodbClient) -> DynamoDbIdentityRepository {
        DynamoDbIdentityRepository {
            client,
            table_name: DYNAMODB_TABLE_IDENTITIES.into()
        }
    }
}

#[async_trait]
impl IdentityRepository for DynamoDbIdentityRepository<'_> {
    async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError> {
        let id = format!("{}:{}", GOOGLE_IDENTITY_PREFIX, id);
        if let Some(identity) = dynamodb_get_by_id(&self.client, &self.table_name, &id).await? {
            Ok(Some(Identity {
                id: identity.get("id").unwrap().as_s().unwrap().clone(),
                user_id: identity.get("user_id").unwrap().as_s().unwrap().clone(),
            }))
        } else {
            Ok(None)
        }
    }
    async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
        self.client.put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(format!("{}:{}", GOOGLE_IDENTITY_PREFIX, identity.id)))
            .item("user_id", AttributeValue::S(String::from(&user.id)))
            .send().await
    }
}

struct DynamoDbUserRepository<'a> {
    client: &'a DynamodbClient,
    table_name: String,
}

impl <'a> DynamoDbUserRepository<'a> {
    pub fn new(client: &DynamodbClient) -> DynamoDbUserRepository {
        DynamoDbUserRepository {
            client,
            table_name: DYNAMODB_TABLE_IDENTITIES.into()
        }
    }
}

#[async_trait]
impl UserRepository for DynamoDbUserRepository<'_> {
    async fn get_by_id(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
        if let Some(user) = dynamodb_get_by_id(&self.client, &self.table_name, &id).await? {
            Ok(Some(user.try_into()?))
        } else {
            Ok(None)
        }
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, AuthServiceError> {
        if let Some(user) = dynamodb_get_by_key(&self.client, &self.table_name, "email", &email).await? {
            Ok(Some(user.try_into()?))
        } else {
            Ok(None)
        }
    }

    async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
        self.client.put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(String::from(&user.id)))
            .item("name", AttributeValue::S(String::from(&user.name)))
            .item("email", AttributeValue::S(String::from(&user.email)))
            .send().await
    }
}

async fn dynamodb_get_by_key(dynamodb_client: &DynamodbClient, table_name: &str, key: &str, val: &str) -> Result<Option<HashMap<String, AttributeValue>>, AuthServiceError> {
    if let Some(item) = dynamodb_client.get_item()
        .table_name(table_name)
        .key(key, AttributeValue::S(val.to_string()))
        .send()
        .await?.item {
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

async fn dynamodb_get_by_id(dynamodb_client: &DynamodbClient, table_name: &str, id: &str) -> Result<Option<HashMap<String, AttributeValue>>, AuthServiceError> {
    dynamodb_get_by_key(dynamodb_client, table_name,  "id", id).await
}


#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    let cfg: AppConfig = init_config().await;
    let aws_config = aws_config::load_from_env().await;
    let dynamodb_client = DynamodbClient::new(&aws_config);
    let reqwest_client = ReqwestClient::new();

    let app_ctx: AppContext = init_context(cfg, &dynamodb_client, &reqwest_client).await;
    lambda_runtime::run(handler(|req, ctx| auth_handler(req, ctx, &app_ctx))).await?;
    Ok(())
}

async fn auth_handler(
    request: Request,
    ctx: Context,
    app_ctx: &AppContext<'_>,
) -> Result<Response<String>, LambdaError> {
    match request.uri().path() {
        "/auth/login" => login_handler(request, ctx, app_ctx),
        "/auth/callback" => callback_handler(request, ctx, app_ctx).await,
        _ => not_found_handler(request, ctx, app_ctx),
    }
}

fn login_handler(_: Request, _: Context, app_ctx: &AppContext) -> Result<Response<String>, Error> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, app_ctx.google_oauth_provider.get_login_url(REDIRECT_URI))
        .body("".to_string())
        .unwrap())
}

async fn callback_handler(req: Request, _: Context, app_ctx: &AppContext<'_>) -> Result<Response<String>, Error> {
    if let Some(code) = req.query_string_parameters().get("code") {
        let code = code.to_string();

        let token_response = app_ctx.google_oauth_provider.get_token(&code).await?;
        println!("Token Response: {:?}", &token_response);
        let identity = app_ctx.google_oauth_provider.get_identity(&token_response.access_token).await?;

        let user: User = get_or_create_user(identity, &app_ctx.identity_repository, &app_ctx.user_repository, &app_ctx.id_generator).await?;
        let jwt = create_jwt(&user.id, &user.role, app_ctx.cfg.jwt_secret.as_bytes())?;

        Ok(create_cookie_response(jwt))
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Missing code parameter".to_string())
            .unwrap())
    }
}

fn not_found_handler(_: Request, _: Context, _: &AppContext) -> Result<Response<String>, Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("404 Not Found".to_string())
        .unwrap())
}

fn create_cookie_response(jwt: String) -> Response<String> {
    let cookie = Cookie::build(AUTH_COOKIE_NAME, jwt)
        .domain(AUTH_COOKIE_DOMAIN)
        .path(AUTH_COOKIE_PATH)
        .http_only(true)
        .finish();

    Response::builder()
        .status(StatusCode::OK)
        .header("Set-Cookie", cookie.to_string())
        .body("".to_string())
        .unwrap()
}

async fn get_or_create_user<I: IdentityRepository, U: UserRepository>(identity: GoogleIdentity, identity_repo: &I, user_repo: &U, id_generator: &impl Generator<String>) -> Result<User, AuthServiceError> {
    // check to see if there is a corresponding entry in the identities table
    if let Some(matching_identity) = identity_repo.get_by_id(&identity.id).await? {

        // if there is, retrieve the matching user from the users table.
        if let Some(user) = user_repo.get_by_id(&matching_identity.user_id).await? {
            Ok(user)
        } else {
            Err(AuthServiceError::IdentityUserNotFound)
        }
    } else {
        // If not, need to insert a new identity.

        // Check for a user with a matching email
        let user = user_repo.get_by_email(&identity.email).await?;

        if let Some(user) = user {
            // if there is one, insert a new identity for this user
            let new_identity: Identity = Identity {
                id: identity.id.clone(),
                user_id: user.id.clone()
            };
            identity_repo.insert(&new_identity, &user).await?;
            Ok(user)
        } else {
            // if there isn't, create a new user entry.
            let user = User {
                id: id_generator.next_id(),
                name: identity.name.clone(),
                email: identity.email.clone(),
                role: Role::User
            };

            user_repo.insert(&user).await?;
            let new_identity: Identity = Identity {
                id: identity.id.clone(),
                user_id: user.id.clone()
            };
            identity_repo.insert(&new_identity, &user).await?;
            Ok(user)
        }
    }
}

fn create_jwt(uid: &str, role: &Role, secret: &[u8]) -> Result<String, AuthServiceError> {
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

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|_| AuthServiceError::JWTCreationError)
}

async fn init_config() -> AppConfig {
    let jwt_secret = env::var("JWT_SECRET").expect("Missing JWT_SECRET env var");
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID env var");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET env var");

    let google_oauth_config = GoogleOAuthConfig {
        client_id,
        client_secret,
        token_url: GOOGLE_ENDPOINT_TOKEN.to_string(),
        identity_url: GOOGLE_ENDPOINT_IDENTITY.to_string(),
    };

    AppConfig {
        google_oauth_config,
        jwt_secret,
    }
}

async fn init_context<'a>(cfg: AppConfig, dynamodb_client: &'a DynamodbClient, reqwest_client: &'a ReqwestClient) -> AppContext<'a> {
    let id_generator = StringGenerator::default();

    let google_oauth_provider = GoogleOAuthProvider::new(
        reqwest_client,
        cfg.google_oauth_config.client_id.clone(),
        cfg.google_oauth_config.client_secret.clone(),
    );
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
    use std::str::FromStr;
    use lambda_http::http::Uri;
    use super::*;
    use wiremock::matchers::body_string;

    #[tokio::test]
    async fn init_config_returns_a_working_config() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let result = init_config().await;

        assert_eq!(result.google_oauth_config.client_id, "TEST_CLIENT_ID");
        assert_eq!(result.google_oauth_config.client_secret, "TEST_CLIENT_SECRET");
        assert_eq!(result.jwt_secret, "TEST_JWT_SECRET");
    }

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

    #[tokio::test]
    async fn login_handler_returns_well_formed_301() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = init_config().await;
        let shared_config = aws_config::load_from_env().await;
        let dynamodb_client = DynamodbClient::new(&shared_config);
        let reqwest_client = ReqwestClient::new();

        let app_ctx: AppContext = init_context(cfg, &dynamodb_client, &reqwest_client).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/login").unwrap();
        let ctx = Context::default();

        let result = login_handler(req, ctx, &app_ctx).unwrap();
        assert_eq!(result.status(), StatusCode::FOUND);
        assert_eq!(result.headers().get("location").unwrap(), "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fsolvastro.com%2Fauth%2Fcallback&prompt=consent&response_type=code&client_id=TEST_CLIENT_ID&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&access_type=offline");
    }

    #[tokio::test]
    async fn get_or_create_user_returns_matching_user_if_present() {
        struct FakeIdentityRepository {}
        #[async_trait]
        impl IdentityRepository for FakeIdentityRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError> {
                Ok(Some(Identity {
                    id: "GOOG:ID_001".to_string(),
                    user_id: "MCBOB_BUTTERSCHNITZ_ID".to_string()
                }))
            }

            async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(if id == "MCBOB_BUTTERSCHNITZ_ID" {
                    Some(User {
                        id: "MCBOB_BUTTERSCHNITZ_ID".to_string(),
                        name: "MCBOB BUTTERSCHNITZ".to_string(),
                        email: "mcbob@butterschnitz.com".to_string(),
                        role: Role::User
                    })
                } else {
                    None
                })
            }

            async fn get_by_email(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                unimplemented!()
            }

            async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let user_repo = FakeUserRepository {};

        let identity = GoogleIdentity {
            name: "MCBOB BUTTERSCHNITZ".to_string(),
            picture: ":-)".to_string(),
            email: "mcbob@butterschnitz.com".to_string(),
            id: "GOOG:ID_001".to_string(),
            verified_email: false
        };

        let id_generator = StringGenerator::default();

        let result = get_or_create_user(
            identity,
            &identity_repo,
            &user_repo,
            &id_generator
        ).await.unwrap();

        assert_eq!(result.id, "MCBOB_BUTTERSCHNITZ_ID");
        assert_eq!(result.email, "mcbob@butterschnitz.com");
    }

    #[tokio::test]
    async fn get_or_create_user_returns_identityusernotfounderror_if_id_found_but_no_user() {
        struct FakeIdentityRepository {}
        #[async_trait]
        impl IdentityRepository for FakeIdentityRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError> {
                Ok(Some(Identity {
                    id: "GOOG:ID_001".to_string(),
                    user_id: "MCBOB_BUTTERSCHNITZ_ID".to_string()
                }))
            }

            async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(None)
            }

            async fn get_by_email(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                unimplemented!()
            }

            async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let user_repo = FakeUserRepository {};

        let identity = GoogleIdentity {
            name: "MCBOB BUTTERSCHNITZ".to_string(),
            picture: ":-)".to_string(),
            email: "mcbob@butterschnitz.com".to_string(),
            id: "GOOG:ID_001".to_string(),
            verified_email: false
        };

        let id_generator = StringGenerator::default();

        let result = get_or_create_user(
            identity,
            &identity_repo,
            &user_repo,
            &id_generator
        ).await.err();

        // TODO: explicitly check for AuthServiceError::IdentityUserNotFound
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn get_or_create_user_returns_user_and_inserts_identity_if_no_identity_but_user_with_same_email() {
        struct FakeIdentityRepository {
        }

        #[async_trait]
        impl IdentityRepository for FakeIdentityRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError> {
                Ok(None)
            }

            async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                Ok(PutItemOutput::builder().build())
            }
        }
        let mut identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(None)
            }

            async fn get_by_email(&self, id: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(Some(User {
                    id: "ID_NORMAN".to_string(),
                    name: "Norman McDingleton".to_string(),
                    email: "norman@gmail.com".to_string(),
                    role: Role::User
                }))
            }

            async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let user_repo = FakeUserRepository {};

        let identity = GoogleIdentity {
            name: "Norman McDingleton".to_string(),
            email: "norman@gmail.com".to_string(),
            picture: ":-)".to_string(),
            id: "GOOG:ID_002".to_string(),
            verified_email: true
        };

        let id_generator = StringGenerator::default();

        let result = get_or_create_user(
            identity,
            &identity_repo,
            &user_repo,
            &id_generator
        ).await.unwrap();

        assert_eq!(result.id, "ID_NORMAN");
        // TODO: test identity actually inserted
        //assert!(inserted);
    }

    #[tokio::test]
    async fn get_or_create_user_inserts_user_and_identity_if_no_identity_or_user_found() {
        struct FakeIdentityRepository {
        }

        #[async_trait]
        impl IdentityRepository for FakeIdentityRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<Identity>, AuthServiceError> {
                Ok(None)
            }

            async fn insert(&self, identity: &Identity, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                Ok(PutItemOutput::builder().build())
            }
        }
        let mut identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, _: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(None)
            }

            async fn get_by_email(&self, _: &str) -> Result<Option<User>, AuthServiceError> {
                Ok(None)
            }

            async fn insert(&self, _: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
                Ok(PutItemOutput::builder().build())
            }
        }
        let user_repo = FakeUserRepository {};

        let identity = GoogleIdentity {
            name: "Norman McDingleton".to_string(),
            email: "norman@gmail.com".to_string(),
            picture: ":-)".to_string(),
            id: "GOOG:ID_002".to_string(),
            verified_email: true
        };

        #[derive(Default)]
        struct FakeIdGenerator {}
        impl Generator<String> for FakeIdGenerator {
            fn next_id(&self) -> String {
                "ID_999".to_string()
            }
        }

        let id_generator = FakeIdGenerator{};

        let result = get_or_create_user(
            identity,
            &identity_repo,
            &user_repo,
            &id_generator
        ).await.unwrap();

        assert_eq!(result.id, "ID_999");
        // TODO: test identity and user actually inserted
        //assert!(inserted);
    }

    #[tokio::test]
    async fn not_found_handler_gives_404() {
        env::set_var("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET");
        env::set_var("JWT_SECRET", "TEST_JWT_SECRET");
        let cfg = init_config().await;
        let shared_config = aws_config::load_from_env().await;
        let dynamodb_client = DynamodbClient::new(&shared_config);
        let reqwest_client = ReqwestClient::new();

        let app_ctx: AppContext = init_context(cfg, &dynamodb_client, &reqwest_client).await;

        let mut req = Request::default();
        *req.uri_mut() = Uri::from_str("https://example.local/some-weird-path").unwrap();
        let ctx = Context::default();

        let result = not_found_handler(req, ctx, &app_ctx).unwrap();
        assert_eq!(result.status(), 404);
    }

    #[test]
    fn create_jwt_successfully_creates_a_jwt() {
        let uid = "userid-001";
        let role: Role = Role::Admin;

        let jwt_secret =  b"secret";

        let jwt = create_jwt(uid, &role, jwt_secret).unwrap();

        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9";
        assert_eq!(jwt.split('.').collect::<Vec<_>>()[0], expected);
    }

    #[test]
    fn create_cookie_response_gives_a_well_formed_cookie() {
        let jwt = "A_JWT".to_string();
        let result = create_cookie_response(jwt).into_parts();

        assert_eq!(result.0.status, 200);
        assert_eq!(result.0.headers.get("set-cookie").unwrap(), "auth=A_JWT; HttpOnly; Path=/; Domain=solvastro.com");
        assert_eq!(result.1, "");
    }
}
