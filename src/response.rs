use crate::{CoapMessageExt, CoapRequest, MessageClass, MessageType, ResponseType, packet::Packet};

/// The CoAP response.
#[derive(Clone, Debug)]
pub struct CoapResponse<T: Packet> {
    message: T,
}

impl<'a, T:'a + Packet> CoapMessageExt<'a, T> for CoapResponse<T> {
fn get_message(&self) -> &T {
    &self.message
}
    fn get_message_mut(&mut self) -> &mut T {
        &mut self.message
    }
}

impl<T: Packet> CoapResponse<T> {
    /// Creates a new response.
    pub fn from_request(request: &CoapRequest<T>, response_type: ResponseType) -> Option<CoapResponse<T>> {
        let mut packet = T::new();

        if let Err(_) = packet.set_type_from_request(request.get_type()) {
            return None;
        }

        packet.set_code_from_message_class(MessageClass::Response(
          response_type
        ));

        if let Some(m) = request.get_message_id() {
            packet.set_message_id(m)
        };

        packet.set_token(request.get_token().clone());

        Some(CoapResponse { message: packet })
    }

    pub fn from_packet(packet: T) -> Option<CoapResponse<T>>{
        match packet.get_message_class() {
            MessageClass::Response(_) => {},
            _ => return None
        }
        match packet.get_type() {
            Some(MessageType::Acknowledgement) => {},
            Some(MessageType::Reset) => {},
            None => {},
            _ => return None
        }
        Some(CoapResponse {
            message: packet
        })
    }

    /// Sets the status.
    pub fn set_response_status(&mut self, status: ResponseType) {
        self.message.set_code_from_message_class(MessageClass::Response(status))
    }

    pub fn get_response_status(&self) -> Option<ResponseType> {
        match self.get_message().get_message_class() {
            MessageClass::Response(rt) => Some(rt),
            _ => None
        }
        }

    pub fn set_observe_value(&mut self, value: Vec<u8>) {
        self.message.set_observe(value)
    }

    pub fn get_observe_value(&self) -> Option<&Vec<u8>> {
        self.message.get_observe()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MessageType;
    use crate::RequestType;
    use crate::PacketUdp;
    use crate::PacketTcp;

    #[test]
    fn test_new_response_from_request_valid() {
        for mtyp in vec![MessageType::Confirmable, MessageType::NonConfirmable]
        {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            packet.set_code_from_message_class(MessageClass::Request(RequestType::Get));
            let request = CoapRequest::from_packet(packet.clone()).unwrap();
            let response: Option<CoapResponse<PacketUdp>> =
                CoapResponse::from_request(&request, ResponseType::Content);

            assert_eq!(packet.get_payload(), response.unwrap().get_payload());
        }
    }

    #[test]
    fn test_new_response_from_packet_valid() {
        for mtyp in vec![MessageType::Acknowledgement, MessageType::Reset] {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            packet.set_code_from_message_class(MessageClass::Response(ResponseType::Content));
            let response: Option<CoapResponse<PacketUdp>> =
                CoapResponse::from_packet(packet);
        assert!(response.is_some());
        }
            let mut packet = PacketTcp::new();
            packet.set_code_from_message_class(MessageClass::Response(ResponseType::Content));
            let response: Option<CoapResponse<PacketTcp>> =
                CoapResponse::from_packet(packet);
        assert!(response.is_some());

    }

    #[test]
    fn test_new_response_from_packet_invalid_because_of_wrong_message_type() {
        for mtyp in vec![MessageType::Confirmable, MessageType::NonConfirmable] {
            let mut packet = PacketUdp::new();
            packet.set_type(mtyp);
            packet.set_code_from_message_class(MessageClass::Response(ResponseType::Content));
            let response: Option<CoapResponse<PacketUdp>> =
                CoapResponse::from_packet(packet);
        assert!(response.is_none());
        }
    }
}
