use alloc::{collections::LinkedList, vec::Vec};
use core::convert::TryFrom;

use crate::{error::MessageError, packet::*, MessageClass, MessageType};

use super::header::{Header, HeaderRaw};

/// The CoAP packet.
#[derive(Debug, Clone, Default)]
pub struct PacketUdp {
    header: Header,
    token: Vec<u8>,
    options: Options,
    payload: Vec<u8>,
}

impl Packet for PacketUdp {
    /// Creates a new packet.
    fn new() -> PacketUdp {
        Default::default()
    }

    /// Returns an iterator over the options of the packet.
    fn options(&self) -> OptionsIter<'_> {
        self.options.iter()
    }

    /// Sets the token.
    fn set_token(&mut self, token: Vec<u8>) {
        self.header.set_token_length(token.len() as u8);
        self.token = token;
    }

    /// Returns the token.
    fn get_token(&self) -> &Vec<u8> {
        &self.token
    }

    /// Sets an option's values.
    fn set_option(&mut self, tp: CoapOption, value: LinkedList<Vec<u8>>) {
        self.options.insert(tp.into(), value);
    }

    /// Returns an option's values.
    fn get_option(&self, tp: CoapOption) -> Option<&LinkedList<Vec<u8>>> {
        self.options.get(&tp.into())
    }

    /// Adds an option value.
    fn add_option(&mut self, tp: CoapOption, value: Vec<u8>) {
        let num = tp.into();
        if let Some(list) = self.options.get_mut(&num) {
            list.push_back(value);
            return;
        }

        let mut list = LinkedList::new();
        list.push_back(value);
        self.options.insert(num, list);
    }

    /// Removes an option.
    fn clear_option(&mut self, tp: CoapOption) {
        if let Some(list) = self.options.get_mut(&tp.into()) {
            list.clear()
        }
    }

    /// Sets the content-format.
    fn set_content_format(&mut self, cf: ContentFormat) {
        let content_format: usize = cf.into();
        let msb = (content_format >> 8) as u8;
        let lsb = (content_format & 0xFF) as u8;

        let content_format: Vec<u8> =
            if msb == 0 { vec![lsb] } else { vec![msb, lsb] };

        self.add_option(CoapOption::ContentFormat, content_format);
    }

    /// Returns the content-format.
    fn get_content_format(&self) -> Option<ContentFormat> {
        if let Some(list) = self.get_option(CoapOption::ContentFormat) {
            if let Some(vector) = list.front() {
                if vector.len() == 0 {
                    return None;
                }

                let number =
                    vector.iter().fold(0, |acc, &b| (acc << 8) + b as u16);

                return ContentFormat::try_from(number as usize).ok();
            }
        }

        None
    }

    /// Sets the value of the observe option.
    fn set_observe(&mut self, value: Vec<u8>) {
        self.clear_option(CoapOption::Observe);
        self.add_option(CoapOption::Observe, value);
    }

    /// Returns the value of the observe option.
    fn get_observe(&self) -> Option<&Vec<u8>> {
        if let Some(list) = self.get_option(CoapOption::Observe) {
            if let Some(flag) = list.front() {
                return Some(flag);
            }
        }

        None
    }

    /// Decodes a byte slice and constructs the equivalent packet.
    fn from_bytes(buf: &[u8]) -> Result<PacketUdp, MessageError> {
        let header_result = HeaderRaw::try_from(buf);
        match header_result {
            Ok(raw_header) => {
                let header = Header::from_raw(&raw_header);
                let token_length = header.get_token_length();
                let options_start: usize = 4 + token_length as usize;

                if token_length > 8 {
                    return Err(MessageError::InvalidTokenLength);
                }

                if options_start > buf.len() {
                    return Err(MessageError::InvalidTokenLength);
                }

                let token = buf[4..options_start].to_vec();

                let mut idx = options_start;
                let options = decode_options(&mut idx, &buf)?;
                let payload = if idx < buf.len() {
                    buf[(idx + 1)..buf.len()].to_vec()
                } else {
                    Vec::new()
                };

                Ok(PacketUdp {
                    header,
                    token,
                    options,
                    payload,
                })
            }
            Err(_) => Err(MessageError::InvalidHeader),
        }
    }

    /// Returns a vector of bytes representing the Packet.
    fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut options_bytes = encode_options(&self.options);
        let mut buf_length = 4 + self.payload.len() + self.token.len();
        if self.header.code != MessageClass::Empty && !self.payload.is_empty()
        {
            buf_length += 1;
        }
        buf_length += options_bytes.len();

        if buf_length > 1280 {
            return Err(MessageError::InvalidPacketLength);
        }

        let mut buf: Vec<u8> = Vec::with_capacity(buf_length);
        let header_result = self.header.to_raw().serialize_into(&mut buf);

        match header_result {
            Ok(_) => {
                buf.reserve(self.token.len() + options_bytes.len());
                buf.extend_from_slice(&self.token);
                buf.append(&mut options_bytes);

                if self.header.code != MessageClass::Empty
                    && !self.payload.is_empty()
                {
                    buf.push(0xFF);
                    buf.reserve(self.payload.len());
                    buf.extend_from_slice(&self.payload);
                }
                Ok(buf)
            }
            Err(_) => Err(MessageError::InvalidHeader),
        }
    }

    fn set_code(&mut self, code: &str) {
        self.header.set_code(code);
    }

    fn get_code(&self) -> String {
        self.header.get_code()
    }

    fn set_code_from_message_class(&mut self, message_class: MessageClass) {
        self.header.code = message_class;
    }

    fn get_message_class(&self) -> MessageClass {
        self.header.code
    }

    fn set_type(&mut self, message_type: MessageType) {
        self.header.set_type(message_type)
    }

    fn set_type_from_request(
        &mut self,
        request_message_type: Option<MessageType>,
    ) -> Result<(), MessageError> {
        match request_message_type {
            Some(MessageType::Confirmable) => {
                self.set_type(MessageType::Acknowledgement)
            }
            Some(MessageType::NonConfirmable) => {
                self.set_type(MessageType::NonConfirmable)
            }
            _ => return Err(MessageError::InvalidHeader),
        };
        Ok(())
    }

    fn get_type(&self) -> Option<MessageType> {
        Some(self.header.get_type())
    }

    fn set_message_id(&mut self, message_id: u16) {
        self.header.message_id = message_id;
    }

    fn get_message_id(&self) -> Option<u16> {
        Some(self.header.message_id)
    }

    fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    fn get_payload(&self) -> &Vec<u8> {
        &self.payload
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{RequestType, ResponseType};

    #[test]
    fn test_decode_packet_with_options() {
        let buf = [
            0x44, 0x01, 0x84, 0x9e, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69,
            0x04, 0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31,
        ];
        let packet = PacketUdp::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.header.get_version(), 1);
        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
        assert_eq!(packet.header.get_token_length(), 4);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(RequestType::Get)
        );
        assert_eq!(packet.header.message_id, 33950);
        assert_eq!(*packet.get_token(), vec![0x51, 0x55, 0x77, 0xE8]);
        assert_eq!(packet.options.len(), 2);

        let uri_path = packet.get_option(CoapOption::UriPath);
        assert!(uri_path.is_some());
        let uri_path = uri_path.unwrap();
        let mut expected_uri_path = LinkedList::new();
        expected_uri_path.push_back("Hi".as_bytes().to_vec());
        expected_uri_path.push_back("Test".as_bytes().to_vec());
        assert_eq!(*uri_path, expected_uri_path);

        let uri_query = packet.get_option(CoapOption::UriQuery);
        assert!(uri_query.is_some());
        let uri_query = uri_query.unwrap();
        let mut expected_uri_query = LinkedList::new();
        expected_uri_query.push_back("a=1".as_bytes().to_vec());
        assert_eq!(*uri_query, expected_uri_query);
    }

    #[test]
    fn test_decode_packet_with_payload() {
        let buf = [
            0x64, 0x45, 0x13, 0xFD, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48, 0x65,
            0x6C, 0x6C, 0x6F,
        ];
        let packet = PacketUdp::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.header.get_version(), 1);
        assert_eq!(
            packet.header.get_type(),
            MessageType::Acknowledgement
        );
        assert_eq!(packet.header.get_token_length(), 4);
        assert_eq!(
            packet.header.code,
            MessageClass::Response(ResponseType::Content)
        );
        assert_eq!(packet.header.message_id, 5117);
        assert_eq!(*packet.get_token(), vec![0xD0, 0xE2, 0x4D, 0xAC]);
        assert_eq!(packet.payload, "Hello".as_bytes().to_vec());
    }

    #[test]
    fn test_encode_packet_with_options() {
        let mut packet = PacketUdp::new();
        packet.header.set_version(1);
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code =
            MessageClass::Request(RequestType::Get);
        packet.header.message_id = 33950;
        packet.set_token(vec![0x51, 0x55, 0x77, 0xE8]);
        packet.add_option(CoapOption::UriPath, b"Hi".to_vec());
        packet.add_option(CoapOption::UriPath, b"Test".to_vec());
        packet.add_option(CoapOption::UriQuery, b"a=1".to_vec());
        assert_eq!(
            packet.to_bytes().unwrap(),
            vec![
                0x44, 0x01, 0x84, 0x9e, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48,
                0x69, 0x04, 0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31
            ]
        );
    }

    #[test]
    fn test_encode_packet_with_payload() {
        let mut packet = PacketUdp::new();
        packet.header.set_version(1);
        packet.header.set_type(MessageType::Acknowledgement);
        packet.header.code =
            MessageClass::Response(ResponseType::Content);
        packet.header.message_id = 5117;
        packet.set_token(vec![0xD0, 0xE2, 0x4D, 0xAC]);
        packet.payload = "Hello".as_bytes().to_vec();
        assert_eq!(
            packet.to_bytes().unwrap(),
            vec![
                0x64, 0x45, 0x13, 0xFD, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48,
                0x65, 0x6C, 0x6C, 0x6F
            ]
        );
    }

    #[test]
    fn test_encode_decode_content_format() {
        let mut packet = PacketUdp::new();
        packet.set_content_format(ContentFormat::TextPlain);
        assert_eq!(
            ContentFormat::TextPlain,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_without_msb() {
        let mut packet = PacketUdp::new();
        packet.set_content_format(ContentFormat::ApplicationJSON);
        assert_eq!(
            ContentFormat::ApplicationJSON,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_with_msb() {
        let mut packet = PacketUdp::new();
        packet.set_content_format(ContentFormat::ApplicationSensmlXML);
        assert_eq!(
            ContentFormat::ApplicationSensmlXML,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_decode_empty_content_format() {
        let packet = PacketUdp::new();
        assert!(packet.get_content_format().is_none());
    }

    #[test]
    fn options() {
        let mut p = PacketUdp::new();
        p.add_option(CoapOption::UriHost, vec![0]);
        p.add_option(CoapOption::UriPath, vec![1]);
        p.add_option(CoapOption::ETag, vec![2]);
        p.clear_option(CoapOption::ETag);
        assert_eq!(3, p.options().len());

        let bytes = p.to_bytes().unwrap();
        let mut pp = PacketUdp::from_bytes(&bytes).unwrap();
        assert_eq!(2, pp.options().len());

        let mut values = LinkedList::new();
        values.push_back(vec![3]);
        values.push_back(vec![4]);
        pp.set_option(CoapOption::Oscore, values);
        assert_eq!(3, pp.options().len());
    }

    #[test]
    fn observe() {
        let mut p = PacketUdp::new();
        assert_eq!(None, p.get_observe());
        p.set_observe(vec![0]);
        assert_eq!(Some(&vec![0]), p.get_observe());
    }
}
