use super::{
    header::{MessageClass, MessageType, ResponseType as Status},
    packet::{ObserveOption, Packet},
};

/// The CoAP response.
#[derive(Clone, Debug)]
pub struct CoapResponse<T: Packet> {
    pub message: T,
}

impl<T: Packet> CoapResponse<T> {
    /// Creates a new response.
    pub fn new(request: &T) -> Option<CoapResponse<T>> {
        let mut packet = T::new();

        let response_type = match request.get_type() {
            Some(MessageType::Confirmable) => MessageType::Acknowledgement,
            Some(MessageType::NonConfirmable) => MessageType::NonConfirmable,
            _ => return None,
        };
        packet.set_type(response_type);
        packet.set_code_from_message_class(MessageClass::Response(
            Status::Content,
        ));
        if let Some(m) = request.get_message_id() {
            packet.set_message_id(m)
        };
        packet.set_token(request.get_token().clone());

        Some(CoapResponse { message: packet })
    }

    /// Sets the status.
    pub fn set_status(&mut self, status: Status) {
        self.message
            .set_code_from_message_class(MessageClass::Response(status))
    }

    /// Returns the status.
    pub fn get_status(&self) -> &Status {
        match self.message.get_message_class() {
            MessageClass::Response(Status::Created) => &Status::Created,
            MessageClass::Response(Status::Deleted) => &Status::Deleted,
            MessageClass::Response(Status::Valid) => &Status::Valid,
            MessageClass::Response(Status::Changed) => &Status::Changed,
            MessageClass::Response(Status::Content) => &Status::Content,

            MessageClass::Response(Status::BadRequest) => &Status::BadRequest,
            MessageClass::Response(Status::Unauthorized) => {
                &Status::Unauthorized
            }
            MessageClass::Response(Status::BadOption) => &Status::BadOption,
            MessageClass::Response(Status::Forbidden) => &Status::Forbidden,
            MessageClass::Response(Status::NotFound) => &Status::NotFound,
            MessageClass::Response(Status::MethodNotAllowed) => {
                &Status::MethodNotAllowed
            }
            MessageClass::Response(Status::NotAcceptable) => {
                &Status::NotAcceptable
            }
            MessageClass::Response(Status::PreconditionFailed) => {
                &Status::PreconditionFailed
            }
            MessageClass::Response(Status::RequestEntityTooLarge) => {
                &Status::RequestEntityTooLarge
            }
            MessageClass::Response(Status::UnsupportedContentFormat) => {
                &Status::UnsupportedContentFormat
            }

            MessageClass::Response(Status::InternalServerError) => {
                &Status::InternalServerError
            }
            MessageClass::Response(Status::NotImplemented) => {
                &Status::NotImplemented
            }
            MessageClass::Response(Status::BadGateway) => &Status::BadGateway,
            MessageClass::Response(Status::ServiceUnavailable) => {
                &Status::ServiceUnavailable
            }
            MessageClass::Response(Status::GatewayTimeout) => {
                &Status::GatewayTimeout
            }
            MessageClass::Response(Status::ProxyingNotSupported) => {
                &Status::ProxyingNotSupported
            }
            _ => &Status::UnKnown,
        }
    }

    // Sets the Observe flag.
    pub fn set_observe_flag(&mut self, value: ObserveOption) {
        let value = match value {
            ObserveOption::Register => alloc::vec![], // Value is not present if Register
            ObserveOption::Deregister => alloc::vec![value as u8],
        };
        self.message.set_observe(value);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PacketUdp;
    #[test]
    fn test_new_response_valid() {
        for mtyp in vec![MessageType::Confirmable, MessageType::NonConfirmable]
        {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            let opt_resp: Option<CoapResponse<PacketUdp>> =
                CoapResponse::new(&packet);
            assert!(opt_resp.is_some());

            let response = opt_resp.unwrap();
            assert_eq!(packet.get_payload(), response.message.get_payload());
        }
    }

    #[test]
    fn test_new_response_invalid() {
        let mut packet = PacketUdp::new();
        packet.set_type(MessageType::Acknowledgement);
        assert!(CoapResponse::new(&packet).is_none());
    }
}
