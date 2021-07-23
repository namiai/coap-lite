use crate::{MessageClass, MessageError, Packet, PacketTcp, SignalType, packet::Options};

pub struct CoapSignal {
    message: PacketTcp
}

impl CoapSignal {
    pub fn new(signal_type: SignalType) -> CoapSignal {
        let mut message = PacketTcp::new();
        message.set_code_from_message_class(MessageClass::Signaling(signal_type));
        CoapSignal {
            message
        }
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.message.set_payload(payload);
    }

    pub fn set_options(&mut self, options: Options) {
        for (key, value) in options {
            self.message.set_option(key, value);
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>,MessageError> {
        self.message.to_bytes()
    }
}
