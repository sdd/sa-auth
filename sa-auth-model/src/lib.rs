use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use aws_sdk_dynamodb::error::{GetItemError, PutItemError, QueryError};
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::output::PutItemOutput;
use aws_sdk_dynamodb::types::SdkError;
use aws_sdk_dynamodb::{Client as DynamodbClient, Client, Error as DynamoDbError};
use chrono::DateTime;
use dynomite::error::AttributeError;
use sa_model::{patreon_token::PatreonToken, user::User};
use serde::Deserialize;
use thiserror::Error as ThisError;

#[derive(Deserialize, Debug)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
}

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

    #[error("Missing PatreonStatus")]
    MissingPatStat,
    #[error("PatreonStatus not a string")]
    PatStatNotAString,
    #[error("Missing PatreonConnection")]
    MissingPatCon,
    #[error("PatreonConnection not a bool")]
    PatConNotABool,
}

#[derive(ThisError, Debug)]
pub enum ModelError {
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

    #[error("could not parse user from db")]
    DbUserParseError(#[from] UserParseError),

    #[error("could not query dynamodb")]
    DynamoDbQueryError(#[from] SdkError<QueryError>),

    #[error("Dynomite could not (de)serialize")]
    DynomiteError(#[from] AttributeError),
}

#[async_trait]
pub trait IdentityRepository {
    async fn get_by_id(
        &self,
        id: &str,
        identity_prefix: &str,
    ) -> Result<Option<Identity>, ModelError>;
    async fn insert(
        &self,
        identity: &Identity,
        user: &User,
        identity_prefix: &str,
    ) -> Result<PutItemOutput, SdkError<PutItemError>>;
}

#[async_trait]
pub trait PatreonTokenRepository {
    async fn get_by_user_id(&self, user_id: &str) -> Result<Option<PatreonToken>, ModelError>;
    async fn insert(&self, record: &PatreonToken) -> Result<PutItemOutput, SdkError<PutItemError>>;
}

#[async_trait]
pub trait UserRepository {
    async fn get_by_id(&self, id: &str) -> Result<Option<User>, ModelError>;
    async fn get_by_email(&self, id: &str) -> Result<Option<User>, ModelError>;
    async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>>;
}

pub struct DynamoDbIdentityRepository<'a> {
    client: &'a DynamodbClient,
    table_name: String,
}

impl<'a> DynamoDbIdentityRepository<'a> {
    pub fn new(client: &Client, table_name: String) -> DynamoDbIdentityRepository {
        DynamoDbIdentityRepository { client, table_name }
    }
}

#[async_trait]
impl IdentityRepository for DynamoDbIdentityRepository<'_> {
    async fn get_by_id(
        &self,
        id: &str,
        identity_prefix: &str,
    ) -> Result<Option<Identity>, ModelError> {
        let id = format!("{}:{}", identity_prefix, id);
        if let Some(identity) = dynamodb_get_by_id(self.client, &self.table_name, &id).await? {
            Ok(Some(Identity {
                id: identity.get("id").unwrap().as_s().unwrap().clone(),
                user_id: identity.get("user_id").unwrap().as_s().unwrap().clone(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn insert(
        &self,
        identity: &Identity,
        user: &User,
        identity_prefix: &str,
    ) -> Result<PutItemOutput, SdkError<PutItemError>> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item(
                "id",
                AttributeValue::S(format!("{}:{}", identity_prefix, identity.id)),
            )
            .item("user_id", AttributeValue::S(String::from(&user.id)))
            .send()
            .await
    }
}

pub struct DynamoDbUserRepository<'a> {
    client: &'a DynamodbClient,
    table_name: String,
}

impl<'a> DynamoDbUserRepository<'a> {
    pub fn new(client: &Client, table_name: String) -> DynamoDbUserRepository {
        DynamoDbUserRepository { client, table_name }
    }
}

#[async_trait]
impl UserRepository for DynamoDbUserRepository<'_> {
    async fn get_by_id(&self, id: &str) -> Result<Option<User>, ModelError> {
        if let Some(user) = dynamodb_get_by_id(self.client, &self.table_name, id).await? {
            Ok(Some(user.try_into()?))
        } else {
            Ok(None)
        }
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, ModelError> {
        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name("email")
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(String::from(email)))
            .send()
            .await?;

        if let Some(items) = result.items {
            if !items.is_empty() {
                Ok(Some(items[0].clone().try_into()?))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn insert(&self, user: &User) -> Result<PutItemOutput, SdkError<PutItemError>> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(String::from(&user.id)))
            .item("name", AttributeValue::S(String::from(&user.name)))
            .item("email", AttributeValue::S(String::from(&user.email)))
            .item("role", AttributeValue::S(format!("{:?}", &user.role)))
            .item(
                "patreon_connected",
                AttributeValue::Bool(user.patreon_connected),
            )
            .item(
                "patreon_status",
                AttributeValue::S(format!("{:?}", &user.patreon_status)),
            )
            .send()
            .await
    }
}

pub struct DynamoDbPatreonTokenRepository<'a> {
    client: &'a DynamodbClient,
    table_name: String,
}

impl<'a> DynamoDbPatreonTokenRepository<'a> {
    pub fn new(client: &Client, table_name: String) -> DynamoDbPatreonTokenRepository {
        DynamoDbPatreonTokenRepository { client, table_name }
    }
}

#[async_trait]
impl PatreonTokenRepository for DynamoDbPatreonTokenRepository<'_> {
    async fn get_by_user_id(&self, user_id: &str) -> Result<Option<PatreonToken>, ModelError> {
        if let Some(identity) = dynamodb_get_by_id(self.client, &self.table_name, user_id).await? {
            Ok(Some(PatreonToken {
                id: identity.get("id").unwrap().as_s().unwrap().clone(),
                patreon_id: identity.get("patreon_id").unwrap().as_s().unwrap().clone(),
                access_token: identity
                    .get("access_token")
                    .unwrap()
                    .as_s()
                    .unwrap()
                    .clone(),
                refresh_token: identity
                    .get("refresh_token")
                    .unwrap()
                    .as_s()
                    .unwrap()
                    .clone(),
                scope: identity.get("scope").unwrap().as_s().unwrap().clone(),
                created_at: DateTime::from(
                    DateTime::parse_from_rfc3339(
                        identity.get("created_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap(),
                ),
                expires_at: DateTime::from(
                    DateTime::parse_from_rfc3339(
                        identity.get("expires_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap(),
                ),
                updated_at: DateTime::from(
                    DateTime::parse_from_rfc3339(
                        identity.get("updated_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap(),
                ),
            }))
        } else {
            Ok(None)
        }
    }

    async fn insert(&self, token: &PatreonToken) -> Result<PutItemOutput, SdkError<PutItemError>> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(String::from(&token.id)))
            .item(
                "patreon_id",
                AttributeValue::S(String::from(&token.patreon_id)),
            )
            .item(
                "access_token",
                AttributeValue::S(String::from(&token.access_token)),
            )
            .item(
                "refresh_token",
                AttributeValue::S(String::from(&token.refresh_token)),
            )
            .item("scope", AttributeValue::S(String::from(&token.scope)))
            .item(
                "created_at",
                AttributeValue::S(token.created_at.to_rfc3339()),
            )
            .item(
                "expires_at",
                AttributeValue::S(token.expires_at.to_rfc3339()),
            )
            .item(
                "updated_at",
                AttributeValue::S(token.updated_at.to_rfc3339()),
            )
            .send()
            .await
    }
}

async fn dynamodb_get_by_key(
    dynamodb_client: &DynamodbClient,
    table_name: &str,
    key: &str,
    val: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, ModelError> {
    if let Some(item) = dynamodb_client
        .get_item()
        .table_name(table_name)
        .key(key, AttributeValue::S(val.to_string()))
        .send()
        .await?
        .item
    {
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

async fn dynamodb_get_by_id(
    dynamodb_client: &DynamodbClient,
    table_name: &str,
    id: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, ModelError> {
    dynamodb_get_by_key(dynamodb_client, table_name, "id", id).await
}
