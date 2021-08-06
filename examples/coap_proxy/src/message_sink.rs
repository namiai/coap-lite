extern crate base64;
use crate::redis::Commands;
use base64::encode;
use coap_lite::{Packet, PacketTcp};
use serde::Serialize;
use std::error::Error;

/// Trait to represent message sinks:
/// they receive the CoAP message and forward it somewhere,
/// for example save it into redis or in the file system
pub trait MessageSink {
    fn invoke(&self, message: &SinkMesssage) -> Result<(), MessageSinkError>;
}

#[derive(Serialize)]
pub struct SinkMesssage {
    cn: String,
    content: SinkMessageContent,
}

impl SinkMesssage {
    pub fn from_packet_tcp(cn: &str, path: &str, packet: PacketTcp) -> Self {
        let message_class = packet.get_message_class();
        let payload = packet.get_payload();

        SinkMesssage {
            cn: cn.to_string(),
            content: SinkMessageContent::Response {
                path: path.to_string(),
                code: message_class.to_string(),
                payload: encode(payload),
            },
        }
    }

    pub fn from_connection_event(
        cn: &str,
        event: DeviceConnectionEvent,
    ) -> Self {
        SinkMesssage {
            cn: cn.to_string(),
            content: SinkMessageContent::ConnectionEvent { event },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum SinkMessageContent {
    Response {
        path: String,
        code: String,
        payload: String,
    },
    ConnectionEvent {
        event: DeviceConnectionEvent,
    },
}

#[derive(Serialize)]
pub enum DeviceConnectionEvent {
    Connect,
    Disconnect,
}

#[derive(Debug)]
pub enum MessageSinkError {
    InitError(String),
    ForwardingError(String),
    EncodingError(String),
}

impl std::fmt::Display for MessageSinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitError(e) => {
                write!(f, "Failed to initialize the message sink: {}", e)
            }
            Self::ForwardingError(e) => {
                write!(f, "Failed to forward the message: {}", e)
            }
            Self::EncodingError(e) => {
                write!(f, "Failed to encode the message: {}", e)
            }
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

impl MessageSink for DevNullMessageSink {
    fn invoke(&self, _: &SinkMesssage) -> Result<(), MessageSinkError> {
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

impl MessageSink for RedisMessageSink {
    // the code is synchronous!
    // consider calling it from the blocking tokio task or move to asynchronous version of redis client
    fn invoke(&self, message: &SinkMesssage) -> Result<(), MessageSinkError> {
        let mut connection = self
            .redis_pool
            .get()
            .map_err(|e| MessageSinkError::ForwardingError(e.to_string()))?;

        let message = serde_json::to_string(message)
            .map_err(|e| MessageSinkError::EncodingError(e.to_string()))?;

        connection
            .rpush(&self.key_name, message)
            .map_err(|e| MessageSinkError::ForwardingError(e.to_string()))?;
        Ok(())
    }
}
