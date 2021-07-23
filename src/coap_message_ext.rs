use std::collections::LinkedList;

use crate::{MessageError, MessageType, Packet, packet::{CoapOption, Options}};


pub trait CoapMessageExt<'a, T:'a + Packet> {
    fn get_message(&self) -> &T;
    fn get_message_mut(&mut self) -> &mut T;

    fn set_path(&mut self, path: &str) {
        let message = self.get_message_mut();
        message.set_path(path);
    }
    fn get_path(&self) -> String {
        self.get_message().get_path()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        self.get_message().to_bytes()
    }

    fn set_payload(&mut self, payload: Vec<u8>) {
        self.get_message_mut().set_payload(payload);
    }

    fn get_payload(&'a self) -> &'a Vec<u8> {
        self.get_message().get_payload()
    }

    fn set_options(&mut self, options: Options) {
        for (key, value) in options {
            self.get_message_mut().set_option(key, value);
        }
    }

    fn set_option(&mut self, key:CoapOption, value: LinkedList<Vec<u8>>) {
        self.get_message_mut().set_option(key, value);
    }

    fn get_token(&'a self) -> &'a Vec<u8> {
        self.get_message().get_token()
    }

    fn get_message_id(&self) -> Option<u16> {
        self.get_message().get_message_id()
    }

    fn get_type(&self) -> Option<MessageType> {
        self.get_message().get_type()
    }
}
