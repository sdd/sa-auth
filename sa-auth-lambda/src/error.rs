use aws_sdk_dynamodb::error::{GetItemError, PutItemError, QueryError};
use aws_sdk_dynamodb::{Error as DynamoDbError, SdkError};
use reqwest::Error as ReqwestError;

use sa_auth_model::{ModelError, UserParseError};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum AuthServiceError {
    #[error("domain model error")]
    DomainModelError(#[from] ModelError),

    #[error("general dynamodb error")]
    DynamoDbError(#[from] DynamoDbError),

    #[error("could not get item from dynamodb")]
    DynamoDbGetItemError(#[from] SdkError<GetItemError>),

    #[error("could not put item into dynamodb")]
    DynamoDbPutItemError(#[from] SdkError<PutItemError>),

    #[error("could not query dynamodb")]
    DynamoDbQueryError(#[from] SdkError<QueryError>),

    #[error("could not create JWT")]
    JWTCreationError,

    #[error("could not parse user from db")]
    DbUserParseError(#[from] UserParseError),

    #[error("request error")]
    RequestError(#[from] ReqwestError),
}
