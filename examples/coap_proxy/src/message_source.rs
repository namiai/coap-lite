extern crate base64;
use crate::redis::Commands;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug)]
pub enum MessageSourceError {
    InitError(String),
    FetchError(String),
    ParseError(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageToDevice {
    pub code: String,
    pub payload: String,
    pub cn: String,
    pub path: String,
}

impl std::fmt::Display for MessageSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitError(e) => write!(f, "Failed to initialize the message sink due to the following error: {}", e),
            Self::FetchError(e) => write!(f, "Failed to fetch the message: {}", e),
            Self::ParseError(e) => write!(f, "Failed to parse the message: {}", e),
        }
    }
}

impl Error for MessageSourceError {}

/// Trait to represent message sources:
/// they fetch message from somewhere and return it to caller
/// NB!: `fetch_new_message` call is blocking, be sure to run it from the right task (i.e tokio::task::spawn_blocking)
pub trait MessageSource {
    fn fetch_new_message(&self)
        -> Result<MessageToDevice, MessageSourceError>;
}

pub struct RedisMessageSource {
    redis_pool: r2d2::Pool<redis::Client>,
    key_name: String,
}

impl RedisMessageSource {
    #[allow(dead_code)]
    pub fn new(
        connection_url: &str,
        key_name: &str,
    ) -> Result<RedisMessageSource, MessageSourceError> {
        let client = redis::Client::open(connection_url)
            .map_err(|e| MessageSourceError::InitError(e.to_string()))?;
        let pool = r2d2::Pool::builder()
            .build(client)
            .map_err(|e| MessageSourceError::InitError(e.to_string()))?;
        Ok(RedisMessageSource {
            redis_pool: pool,
            key_name: key_name.to_owned(),
        })
    }
}

impl MessageSource for RedisMessageSource {
    fn fetch_new_message(
        &self,
    ) -> Result<MessageToDevice, MessageSourceError> {
        let mut connection = self
            .redis_pool
            .get()
            .map_err(|e| MessageSourceError::FetchError(e.to_string()))?;

        let new_msg = connection
            .blpop::<&str, (String, String)>(&self.key_name, 0)
            .map_err(|e| MessageSourceError::FetchError(e.to_string()))?;

        let parsed_msg: MessageToDevice = serde_json::from_str(&new_msg.1)
            .map_err(|e| MessageSourceError::ParseError(e.to_string()))?;
        trace!("New message to send to device {:?}", parsed_msg);
        Ok(parsed_msg)
    }
}
