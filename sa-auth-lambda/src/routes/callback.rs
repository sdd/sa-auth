use async_trait::async_trait;
use chrono::Utc;
use cookie::Cookie;
use jsonwebtoken::{encode, EncodingKey, Header};
use lambda_http::{Context, Request, RequestExt, Response};
use lambda_http::http::StatusCode;
use lambda_http::lambda_runtime::Error;
use unique_id::Generator;

use papo_provider_core::{Identity as GoogleIdentity, OAuthProvider};
use sa_auth_model::{Claims, Identity, IdentityRepository, ModelError, Role, User, UserRepository};

use crate::{AUTH_COOKIE_DOMAIN, AUTH_COOKIE_NAME, AUTH_COOKIE_PATH};
use crate::context::AppContext;
use crate::error::AuthServiceError;

pub async fn callback_handler(req: Request, _: Context, app_ctx: &AppContext) -> Result<Response<String>, Error> {
    if let Some(code) = req.query_string_parameters().get("code") {
        let code = code.to_string();

        let provider = &app_ctx.google_oauth_provider();

        let token_response = provider.get_token(&code).await?;
        println!("Token Response: {:?}", &token_response);
        let identity = provider.get_identity(&token_response.access_token).await?;

        let user: User = get_or_create_user(identity, &app_ctx.identity_repository(), &app_ctx.user_repository(), &app_ctx.id_generator).await?;
        let jwt = create_jwt(&user.id, &user.role, app_ctx.cfg.jwt_secret.as_bytes())?;

        Ok(create_cookie_response(jwt))
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Missing code parameter".to_string())
            .unwrap())
    }
}

pub fn create_cookie_response(jwt: String) -> Response<String> {
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

pub async fn get_or_create_user<I: IdentityRepository, U: UserRepository>(identity: GoogleIdentity, identity_repo: &I, user_repo: &U, id_generator: &impl Generator<String>) -> Result<User, ModelError> {
    // check to see if there is a corresponding entry in the identities table
    if let Some(matching_identity) = identity_repo.get_by_id(&identity.id, "GOOG").await? {

        // if there is, retrieve the matching user from the users table.
        if let Some(user) = user_repo.get_by_id(&matching_identity.user_id).await? {
            Ok(user)
        } else {
            Err(ModelError::IdentityUserNotFound)
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
            identity_repo.insert(&new_identity, &user, "GOOG").await?;
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
            identity_repo.insert(&new_identity, &user, "GOOG").await?;
            Ok(user)
        }
    }
}

pub fn create_jwt(uid: &str, role: &Role, secret: &[u8]) -> Result<String, AuthServiceError> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(3600))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    let header = Header::default();

    encode(&header, &claims, &EncodingKey::from_secret(secret))
        .map_err(|_| AuthServiceError::JWTCreationError)
}

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::error::PutItemError;
    use aws_sdk_dynamodb::output::PutItemOutput;
    use aws_sdk_dynamodb::SdkError;
    use unique_id::string::StringGenerator;
    use sa_auth_model::ModelError;

    use crate::routes::callback::{create_cookie_response, create_jwt, get_or_create_user};
    use super::*;

    #[tokio::test]
    async fn get_or_create_user_returns_matching_user_if_present() {
        struct FakeIdentityRepository {}
        #[async_trait]
        impl IdentityRepository for FakeIdentityRepository {
            async fn get_by_id(&self, _: &str, _: &str) -> Result<Option<Identity>, ModelError> {
                Ok(Some(Identity {
                    id: "GOOG:ID_001".to_string(),
                    user_id: "MCBOB_BUTTERSCHNITZ_ID".to_string()
                }))
            }

            #[no_coverage]
            async fn insert(&self, _: &Identity, _: &User, _: &str) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, id: &str) -> Result<Option<User>, ModelError> {
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

            #[no_coverage]
            async fn get_by_email(&self, _: &str) -> Result<Option<User>, ModelError> {
                unimplemented!()
            }

            #[no_coverage]
            async fn insert(&self, _: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
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
            async fn get_by_id(&self, _: &str, _: &str) -> Result<Option<Identity>, ModelError> {
                Ok(Some(Identity {
                    id: "GOOG:ID_001".to_string(),
                    user_id: "MCBOB_BUTTERSCHNITZ_ID".to_string()
                }))
            }

            #[no_coverage]
            async fn insert(&self, _: &Identity, _: &User, _: &str) -> Result<PutItemOutput, SdkError<PutItemError>> {
                unimplemented!()
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, _: &str) -> Result<Option<User>, ModelError> {
                Ok(None)
            }

            #[no_coverage]
            async fn get_by_email(&self, _: &str) -> Result<Option<User>, ModelError> {
                unimplemented!()
            }

            #[no_coverage]
            async fn insert(&self, _: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
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
            async fn get_by_id(&self, _: &str, _: &str) -> Result<Option<Identity>, ModelError> {
                Ok(None)
            }

            async fn insert(&self, _: &Identity, _: &User, _: &str) -> Result<PutItemOutput, SdkError<PutItemError>> {
                Ok(PutItemOutput::builder().build())
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, _: &str) -> Result<Option<User>, ModelError> {
                Ok(None)
            }

            async fn get_by_email(&self, _: &str) -> Result<Option<User>, ModelError> {
                Ok(Some(User {
                    id: "ID_NORMAN".to_string(),
                    name: "Norman McDingleton".to_string(),
                    email: "norman@gmail.com".to_string(),
                    role: Role::User
                }))
            }

            #[no_coverage]
            async fn insert(&self, _: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
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
            async fn get_by_id(&self, _: &str, _: &str) -> Result<Option<Identity>, ModelError> {
                Ok(None)
            }

            async fn insert(&self, _: &Identity, _: &User, _: &str) -> Result<PutItemOutput, SdkError<PutItemError>> {
                Ok(PutItemOutput::builder().build())
            }
        }
        let identity_repo = FakeIdentityRepository {};

        struct FakeUserRepository {}
        #[async_trait]
        impl UserRepository for FakeUserRepository {
            async fn get_by_id(&self, _: &str) -> Result<Option<User>, ModelError> {
                Ok(None)
            }

            async fn get_by_email(&self, _: &str) -> Result<Option<User>, ModelError> {
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

    #[test]
    fn create_jwt_successfully_creates_a_jwt() {
        let uid = "userid-001";
        let role: Role = Role::Admin;

        let jwt_secret =  b"secret";

        let jwt = create_jwt(uid, &role, jwt_secret).unwrap();

        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
        assert_eq!(jwt.split('.').collect::<Vec<_>>()[0], expected);
    }

    #[test]
    fn create_cookie_response_gives_a_well_formed_cookie() {
        let jwt = "A_JWT".to_string();
        let result = create_cookie_response(jwt).into_parts();

        assert_eq!(result.0.status, 200);
        assert_eq!(result.0.headers.get("set-cookie").unwrap(), "sa-auth=A_JWT; HttpOnly; Path=/; Domain=solvastro.com");
        assert_eq!(result.1, "");
    }
}