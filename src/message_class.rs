use crate::{RequestType, ResponseType, SignalType};
use std::fmt;

/// The detailed class (request/response) of a message with the code.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageClass {
    Empty,
    Request(RequestType),
    Response(ResponseType),
    Signaling(SignalType),
    Reserved,
}

impl From<u8> for MessageClass {
    fn from(number: u8) -> MessageClass {
        match number {
            0x00 => MessageClass::Empty,

            0x01 => MessageClass::Request(RequestType::Get),
            0x02 => MessageClass::Request(RequestType::Post),
            0x03 => MessageClass::Request(RequestType::Put),
            0x04 => MessageClass::Request(RequestType::Delete),

            0x40 => MessageClass::Response(ResponseType::Ok),
            0x41 => MessageClass::Response(ResponseType::Created),
            0x42 => MessageClass::Response(ResponseType::Deleted),
            0x43 => MessageClass::Response(ResponseType::Valid),
            0x44 => MessageClass::Response(ResponseType::Changed),
            0x45 => MessageClass::Response(ResponseType::Content),
            0x5F => MessageClass::Response(ResponseType::Continue),

            0x80 => MessageClass::Response(ResponseType::BadRequest),
            0x81 => MessageClass::Response(ResponseType::Unauthorized),
            0x82 => MessageClass::Response(ResponseType::BadOption),
            0x83 => MessageClass::Response(ResponseType::Forbidden),

            0x84 => MessageClass::Response(ResponseType::NotFound),
            0x85 => MessageClass::Response(ResponseType::MethodNotAllowed),
            0x86 => MessageClass::Response(ResponseType::NotAcceptable),
            0x8C => MessageClass::Response(ResponseType::PreconditionFailed),
            0x8D => {
                MessageClass::Response(ResponseType::RequestEntityTooLarge)
            }
            0x8F => {
                MessageClass::Response(ResponseType::UnsupportedContentFormat)
            }
            0x88 => {
                MessageClass::Response(ResponseType::RequestEntityIncomplete)
            }
            0x9d => MessageClass::Response(ResponseType::TooManyRequests),

            0xA0 => MessageClass::Response(ResponseType::InternalServerError),
            0xA1 => MessageClass::Response(ResponseType::NotImplemented),
            0xA2 => MessageClass::Response(ResponseType::BadGateway),
            0xA3 => MessageClass::Response(ResponseType::ServiceUnavailable),
            0xA4 => MessageClass::Response(ResponseType::GatewayTimeout),
            0xA5 => MessageClass::Response(ResponseType::ProxyingNotSupported),
            0xE1 => MessageClass::Signaling(SignalType::CSM),
            0xE2 => MessageClass::Signaling(SignalType::Ping),
            0xE3 => MessageClass::Signaling(SignalType::Pong),
            0xE4 => MessageClass::Signaling(SignalType::Release),
            0xE5 => MessageClass::Signaling(SignalType::Abort),
            _ => MessageClass::Reserved,
        }
    }
}

impl From<MessageClass> for u8 {
    fn from(class: MessageClass) -> u8 {
        match class {
            MessageClass::Empty => 0x00,

            MessageClass::Request(RequestType::Get) => 0x01,
            MessageClass::Request(RequestType::Post) => 0x02,
            MessageClass::Request(RequestType::Put) => 0x03,
            MessageClass::Request(RequestType::Delete) => 0x04,

            MessageClass::Signaling(SignalType::CSM) => 0xE1,
            MessageClass::Signaling(SignalType::Ping) => 0xE2,
            MessageClass::Signaling(SignalType::Pong) => 0xE3,
            MessageClass::Signaling(SignalType::Release) => 0xE4,
            MessageClass::Signaling(SignalType::Abort) => 0xE5,

            MessageClass::Response(ResponseType::Ok) => 0x40,
            MessageClass::Response(ResponseType::Created) => 0x41,
            MessageClass::Response(ResponseType::Deleted) => 0x42,
            MessageClass::Response(ResponseType::Valid) => 0x43,
            MessageClass::Response(ResponseType::Changed) => 0x44,
            MessageClass::Response(ResponseType::Content) => 0x45,
            MessageClass::Response(ResponseType::Continue) => 0x5F,

            MessageClass::Response(ResponseType::BadRequest) => 0x80,
            MessageClass::Response(ResponseType::Unauthorized) => 0x81,
            MessageClass::Response(ResponseType::BadOption) => 0x82,
            MessageClass::Response(ResponseType::Forbidden) => 0x83,
            MessageClass::Response(ResponseType::NotFound) => 0x84,
            MessageClass::Response(ResponseType::MethodNotAllowed) => 0x85,
            MessageClass::Response(ResponseType::NotAcceptable) => 0x86,
            MessageClass::Response(ResponseType::PreconditionFailed) => 0x8C,
            MessageClass::Response(ResponseType::RequestEntityTooLarge) => {
                0x8D
            }
            MessageClass::Response(ResponseType::UnsupportedContentFormat) => {
                0x8F
            }
            MessageClass::Response(ResponseType::RequestEntityIncomplete) => {
                0x88
            }
            MessageClass::Response(ResponseType::TooManyRequests) => 0x9d,

            MessageClass::Response(ResponseType::InternalServerError) => 0xA0,
            MessageClass::Response(ResponseType::NotImplemented) => 0xA1,
            MessageClass::Response(ResponseType::BadGateway) => 0xA2,
            MessageClass::Response(ResponseType::ServiceUnavailable) => 0xA3,
            MessageClass::Response(ResponseType::GatewayTimeout) => 0xA4,
            MessageClass::Response(ResponseType::ProxyingNotSupported) => 0xA5,

            _ => 0xFF,
        }
    }
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let code: u8 = (*self).into();
        let class_code = (0xE0 & code) >> 5;
        let detail_code = 0x1F & code;
        write!(f, "{}.{:02}", class_code, detail_code)
    }
}

impl Default for MessageClass {
    fn default() -> Self {
        MessageClass::Empty
    }
}
