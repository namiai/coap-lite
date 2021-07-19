extern crate base64;
use crate::redis::Commands;
use base64::decode;
use coap_lite::Packet;
use std::error::Error;

#[derive(Debug)]
pub enum MessageSourceError {
    InitError(String),
    MessageFetchingError(String)
}

impl std::fmt::Display for MessageSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitError(e) => write!(f, "Failed to initialize the message sink due to the following error: {}", e),
            Self::MessageFetchingError(e) => write!(f, "Failed to fetch the message: {}", e),
        }
    }
}

impl Error for MessageSourceError {}

pub trait MessageSource<T> where T:Packet {
    fn fetch_new_message(&self) -> Result<(T, String), MessageSourceError>;
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

impl<T> MessageSource<T> for RedisMessageSource
where
    T: Packet,
{
    fn fetch_new_message(&self) -> Result<(T, String), MessageSourceError> {
        let mut connection = self.redis_pool.get().map_err(|e| {
            MessageSourceError::MessageFetchingError(e.to_string())
        })?;

        let new_msg = connection
            .blpop::<&str, (String, String)>(&self.key_name, 0)
            .map_err(|e| {
                MessageSourceError::MessageFetchingError(e.to_string())
            })?;

        let cn = "123".to_string();
        trace!("New message to send to device {}: {}", new_msg.1);
        Ok((T::new(), cn))
    }
}
