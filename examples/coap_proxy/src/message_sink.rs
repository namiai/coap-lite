extern crate base64;
use crate::redis::Commands;
use base64::encode;
use coap_lite::Packet;
use serde_json::json;
use std::error::Error;

/// Trait to represent message sinks:
/// they receive the CoAP message and forward it somewhere,
/// for example save it into redis or in the file system
pub trait MessageSink<T>
where
    T: Packet,
{
    fn process_incoming_message(
        &self,
        message: T,
        cn: &str,
        path: &str,
    ) -> Result<(), MessageSinkError>;
}

#[derive(Debug)]
pub enum MessageSinkError {
    InitError(String),
    MessageForwardingError(String),
}

impl std::fmt::Display for MessageSinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitError(e) => write!(f, "Failed to initialize the message sink due to the following error: {}", e),
            Self::MessageForwardingError(e) => write!(f, "Failed to forward the message due to the following error: {}", e)
        }
    }
}

impl Error for MessageSinkError {}

/// The simplest possible message sink
/// Just discards the message
pub struct DevNullMessageSink {}

impl DevNullMessageSink {
    #[allow(dead_code)]
    pub fn new() -> DevNullMessageSink {
        DevNullMessageSink {}
    }
}

impl<T> MessageSink<T> for DevNullMessageSink
where
    T: Packet,
{
    fn process_incoming_message(
        &self,
        _: T,
        _: &str,
        _: &str,
    ) -> Result<(), MessageSinkError> {
        Ok(())
    }
}

/// Message sink that saves data to redis DB
/// RPUSHes the json-encoded message to the key defined during the sink init
pub struct RedisMessageSink {
    redis_pool: r2d2::Pool<redis::Client>,
    key_name: String,
}

impl RedisMessageSink {
    /// Constructs new redis sink with specified connection string and key name
    pub fn new(
        connection_url: &str,
        key_name: &str,
    ) -> Result<RedisMessageSink, MessageSinkError> {
        let client = redis::Client::open(connection_url)
            .map_err(|e| MessageSinkError::InitError(e.to_string()))?;
        let pool = r2d2::Pool::builder()
            .build(client)
            .map_err(|e| MessageSinkError::InitError(e.to_string()))?;
        Ok(RedisMessageSink {
            redis_pool: pool,
            key_name: key_name.to_owned(),
        })
    }
}

impl<T> MessageSink<T> for RedisMessageSink
where
    T: Packet,
{
    // the code is synchronous!
    // consider calling it from the blocking tokio task or move to asynchronous version of redis client
    fn process_incoming_message(
        &self,
        message: T,
        cn: &str,
        path: &str,
    ) -> Result<(), MessageSinkError> {
        let message_class = message.get_message_class();
        let payload = message.get_payload();

        let sink_message = json!({
            "code": message_class.to_string(),
            "payload": encode(payload),
            "cn": cn,
            "path": path
        });

        let mut connection = self.redis_pool.get().map_err(|e| {
            MessageSinkError::MessageForwardingError(e.to_string())
        })?;

        connection
            .rpush(&self.key_name, sink_message.to_string())
            .map_err(|e| {
                MessageSinkError::MessageForwardingError(e.to_string())
            })?;
        Ok(())
    }
}
