use crate::{CoapMessageExt, PacketUdp};

use super::{
    packet::{ObserveOption, Packet},
    MessageClass, RequestType, MessageType
};

/// The CoAP request.
#[derive(Clone, Debug)]
pub struct CoapRequest<T: Packet> {
    message: T,
}

impl<'a, T:'a + Packet> CoapMessageExt<'a, T> for CoapRequest<T> {
    fn get_message(&self) -> &T {
        &self.message
    }
    fn get_message_mut(&mut self) -> &mut T {
        &mut self.message
    }
}

impl<T: Packet> CoapRequest<T> {
    pub fn new(request_type: RequestType) -> CoapRequest<T> {
        let mut message = T::new();
        message.set_code_from_message_class(MessageClass::Request(request_type));
        CoapRequest {
            message
        }
    }

    /// Creates a request from a packet.
    pub fn from_packet(
        packet: T,
    ) -> Option<CoapRequest<T>> {
        match packet.get_message_class() {
            MessageClass::Request(_) => {},
            _ => return None
        }
        match packet.get_type() {
            Some(MessageType::Confirmable) => {},
            Some(MessageType::NonConfirmable) => {},
            None => {},
            _ => return None
        }
        Some(CoapRequest {
            message: packet,
        })
    }

    /// Sets the method.
    pub fn set_request_type(&mut self, request_type: RequestType) {
        self.message
            .set_code_from_message_class(MessageClass::Request(request_type));
    }

    pub fn get_request_type(&self) -> RequestType {
        match self.message.get_message_class() {
            MessageClass::Request(rt) => rt,
            _ => panic!("Request type must always have message class Request"),
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

    /// Returns the flag in the Observe option.
    pub fn get_observe_flag(&self) -> Option<ObserveOption> {
        self.get_message().get_observe()
            .and_then(|option| match option.get(0) {
                Some(&x) if x == ObserveOption::Register as u8 => {
                    Some(ObserveOption::Register)
                }
                Some(&x) if x == ObserveOption::Deregister as u8 => {
                    Some(ObserveOption::Deregister)
                }
                Some(_) => None,
                // Value is Register by default if not present
                None => Some(ObserveOption::Register),
            })
    }

    pub fn set_token(&mut self, token: Vec<u8>) {
        self.message.set_token(token)
    }

    pub fn set_message_id(&mut self, message_id: u16) {
       self.message.set_message_id(message_id)
    }

}

impl CoapRequest<PacketUdp> {
    pub fn set_type(&mut self, message_type: MessageType) {
        self.message.set_type(message_type);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PacketTcp;
    use crate::PacketUdp;
    use crate::ResponseType;
    use crate::CoapOption;

    #[test]
    fn test_creation_from_packet() {
        let mut packet = PacketTcp::new();
        packet.set_code_from_message_class(MessageClass::Request(RequestType::Get));
        assert!(CoapRequest::from_packet(packet).is_some());

        let mut packet = PacketTcp::new();
        packet.set_code_from_message_class(MessageClass::Response(ResponseType::BadGateway));
        assert!(CoapRequest::from_packet(packet).is_none());
    }

    #[test]
    fn test_method() {
        let mut request:CoapRequest<PacketUdp> = CoapRequest::new(RequestType::Get);
        request.set_request_type(RequestType::Get);
        assert_eq!("0.01", request.message.get_code());

        request.set_request_type(RequestType::Post);
        assert_eq!("0.02", request.message.get_code());

        request.set_request_type(RequestType::Put);
        assert_eq!("0.03", request.message.get_code());

        request.set_request_type(RequestType::Delete);
        assert_eq!("0.04", request.message.get_code());
    }

    #[test]
    fn test_path() {
        let mut request: CoapRequest<PacketUdp> = CoapRequest::new(RequestType::Get);

        let path = "test-interface";
        request
            .message
            .add_option(CoapOption::UriPath, path.as_bytes().to_vec());
        assert_eq!(path, request.get_path());

        let path2 = "test-interface2";
        request.set_path(path2);
        assert_eq!(
            path2.as_bytes().to_vec(),
            *request
                .message
                .get_option(CoapOption::UriPath)
                .unwrap()
                .front()
                .unwrap()
        );

        request.set_path("/test-interface2");
        assert_eq!(
            path2.as_bytes().to_vec(),
            *request
                .message
                .get_option(CoapOption::UriPath)
                .unwrap()
                .front()
                .unwrap()
        );

        let path3 = "test-interface2/";
        request.set_path(path3);
        assert_eq!(path3, request.get_path());
    }
#[test]
    fn test_new_request_from_packet_valid() {
        for mtyp in vec![MessageType::Confirmable, MessageType::NonConfirmable] {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            packet.set_code_from_message_class(MessageClass::Request(RequestType::Get));
            let request: Option<CoapRequest<PacketUdp>> =
                CoapRequest::from_packet(packet);
        assert!(request.is_some());
        }
            let mut packet = PacketUdp::new();
            packet.set_code_from_message_class(MessageClass::Request(RequestType::Get));
            let request: Option<CoapRequest<PacketUdp>> =
                CoapRequest::from_packet(packet);
        assert!(request.is_some());

    }

    #[test]
    fn test_new_response_from_packet_invalid_because_of_wrong_message_type() {
        for mtyp in vec![MessageType::Acknowledgement, MessageType::Reset] {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            packet.set_code_from_message_class(MessageClass::Request(RequestType::Get));
            let request: Option<CoapRequest<PacketUdp>> =
                CoapRequest::from_packet(packet);
        assert!(request.is_none());
        }
    }
}
