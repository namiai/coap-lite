use alloc::{collections::LinkedList, vec::Vec};
use core::convert::TryFrom;
use core::convert::TryInto;
use std::usize;

use crate::Packet;

use crate::{
    error::MessageError,
    packet::{
        decode_options, encode_options, CoapOption, ContentFormat, Options,
        OptionsIter,
    },
    MessageClass, MessageType,
};

macro_rules! u8_to_unsigned_be {
    ($src:ident, $start:expr, $end:expr, $t:ty) => ({
        (0..=$end - $start).rev().fold(
            0, |acc, i| acc | $src[$start+i] as $t << i * 8
        )
    })
}

/// The CoAP packet.
#[derive(Debug, Clone, Default)]
pub struct PacketTcp {
    code: MessageClass,
    token: Vec<u8>,
    options: Options,
    payload: Vec<u8>,
}

impl Packet for PacketTcp {
    /// Creates a new packet.
    fn new() -> PacketTcp {
        Default::default()
    }

    /// Returns an iterator over the options of the packet.
    fn options(&self) -> OptionsIter<'_> {
        self.options.iter()
    }

    /// Sets the token.
    fn set_token(&mut self, token: Vec<u8>) {
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
    fn from_bytes(buf: &[u8]) -> Result<PacketTcp, MessageError> {
        let mut idx: usize = 0;
        let (packet_length, token_length) =
            Self::parse_length(&mut idx, &buf)?;
        if idx >= buf.len() {
            return Err(MessageError::InvalidHeader);
        }
        let code: MessageClass = buf[idx].into();
        idx += 1;
        if token_length > 8 {
            return Err(MessageError::InvalidTokenLength);
        }
        if idx >= buf.len() && token_length > 0 {
            return Err(MessageError::InvalidTokenLength);
        }

        let token = buf[idx..(idx + token_length)].to_vec();
        idx += token_length;

        let pre_options_idx = idx;

        let options = decode_options(&mut idx, &buf)?;
        let options_len = idx - pre_options_idx;
        let payload_len = packet_length - options_len;
        let payload = if packet_length > options_len && idx < buf.len() {
            if payload_len > buf.len() - idx {
                return Err(MessageError::InvalidPacketLength);
            }
            idx += 1;
            buf[idx..idx + payload_len - 1].to_vec()
        } else {
            Vec::new()
        };

        Ok(PacketTcp {
            code,
            token,
            options,
            payload,
        })
    }

    /// Returns a vector of bytes representing the Packet.
    fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut options_bytes = encode_options(&self.options);
        // Length field is a sum of
        // 1. options length
        // 2. payload lenghth
        // 3. payload marker if payload is present
        let mut length = options_bytes.len() + self.payload.len();
        if self.code != MessageClass::Empty && !self.payload.is_empty() {
            length += 1;
        }
        let (length_byte, mut ext_length): (u8, Vec<u8>) =
            PacketTcp::encode_length(length)?;

        let mut buf_length =
            1 + ext_length.len() + 1 + self.token.len() + self.payload.len();
        if self.code != MessageClass::Empty && !self.payload.is_empty() {
            buf_length += 1;
        }
        buf_length += options_bytes.len();

        let mut buf: Vec<u8> = Vec::with_capacity(buf_length);

        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Len  |  TKL  | Extended Length (if any, as chosen by Len) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Code     | Token (if any, TKL bytes) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Options (if any) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1 1 1 1 1 1 1 1|    Payload (if any) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Figure 4: CoAP Frame for Reliable Transports

        */
        let len_token_len_byte = length_byte << 4
            | self.token.len().to_be_bytes().last().copied().unwrap();
        buf.push(len_token_len_byte);
        buf.append(&mut ext_length);
        buf.push(self.code.into());
        buf.extend_from_slice(&self.token);
        buf.append(&mut options_bytes);
        if self.code != MessageClass::Empty && !self.payload.is_empty() {
            buf.push(0xff);
            buf.extend_from_slice(&self.payload);
        }
        Ok(buf)
    }

    /// Sets the message code from a string.
    fn set_code(&mut self, code: &str) {
        let code_vec: Vec<&str> = code.split('.').collect();
        assert_eq!(code_vec.len(), 2);

        let class_code = code_vec[0].parse::<u8>().unwrap();
        let detail_code = code_vec[1].parse::<u8>().unwrap();
        assert_eq!(0xF8 & class_code, 0);
        assert_eq!(0xE0 & detail_code, 0);

        self.code = (class_code << 5 | detail_code).into();
    }

    /// Returns the message code as a string.
    fn get_code(&self) -> String {
        self.code.to_string()
    }

    fn set_code_from_message_class(&mut self, message_class: MessageClass) {
        self.code = message_class;
    }

    fn get_message_class(&self) -> MessageClass {
        self.code
    }

    fn set_type(&mut self, _message_type: MessageType) {
        return;
    }

    fn set_type_from_request(
        &mut self,
        _request_message_type: Option<MessageType>,
    ) -> Result<(), MessageError> {
        Ok(())
    }

    fn get_type(&self) -> Option<MessageType> {
        None
    }

    fn set_message_id(&mut self, _message_id: u16) {
        return;
    }

    fn get_message_id(&self) -> Option<u16> {
        None
    }

    fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload
    }

    fn get_payload(&self) -> &Vec<u8> {
        &self.payload
    }
}

impl PacketTcp {
    pub fn parse_length(
        idx: &mut usize,
        buf: &[u8],
    ) -> Result<(usize, usize), MessageError> {
        if *idx >= buf.len() {
            return Err(MessageError::InvalidHeader);
        }
        let byte = buf[0];
        *idx += 1;
        let mut add_idx = 0;
        let len_byte = byte >> 4;
        let length = match len_byte {
            0..=12 => u32::from(len_byte),
            13 => {
                if *idx >= buf.len() {
                    return Err(MessageError::InvalidHeader);
                }
                add_idx = 1;
                let len = u8_to_unsigned_be!(buf, *idx, *idx, u8);
                u32::from(len) + 13
            }
            14 => {
                if *idx + 1 >= buf.len() {
                    return Err(MessageError::InvalidHeader);
                }
                add_idx = 2;
                let len =
                    u16::from_be(u8_to_unsigned_be!(buf, *idx, *idx + 1, u16));

                u32::from(len) + 269
            }
            15 => {
                if *idx + 2 >= buf.len() {
                    return Err(MessageError::InvalidHeader);
                }
                add_idx = 3;
                // in certain cases we can get overflow because the size will be more > than can fit in u32
                // that's certainly not a valid usecase, so we can throw an error
                u32::from_be(u8_to_unsigned_be!(buf, *idx, *idx + 3, u32))
                    .checked_add(65805)
                    .ok_or(MessageError::InvalidHeader)?
            }
            _ => return Err(MessageError::InvalidHeader),
        };
        let token_length = byte & 0xF;
        *idx += add_idx;
        let length: usize =
            length.try_into().map_err(|_| MessageError::InvalidHeader)?;
        Ok((length, token_length.into()))
    }

    fn encode_length(length: usize) -> Result<(u8, Vec<u8>), MessageError> {
        match length {
            l if l > usize::MAX => Err(MessageError::InvalidPacketLength),
            l @ 0..=12 => {
                Ok((l.to_be_bytes().last().copied().unwrap(), Vec::new()))
            }
            l @ 13..=268 => {
                let base = 13_u8;
                let extension = (l - 13).to_be_bytes().to_vec();
                Ok((base, extension[extension.len() - 1..].to_vec()))
            }
            l @ 269..=65_804 => {
                let base = 14_u8;
                let extension = (l - 269).to_be_bytes().to_vec();
                Ok((base, extension[extension.len() - 2..].to_vec()))
            }
            l @ 65_805..=usize::MAX => {
                #[cfg(target_pointer_width = "64")]
                {
                    if l > 4_295_033_100 {
                        return Err(MessageError::InvalidPacketLength)
                    }
                }
                let base = 15_u8;
                let extension = (l - 65805).to_be_bytes().to_vec();
                Ok((base, extension[extension.len() - 4..].to_vec()))
            }
            _ => Err(MessageError::InvalidPacketLength),
        }
    }


    pub fn check_buf(buf: &[u8]) -> Option<usize> {
        let mut total_bytes_in_packet:usize = 0;
        if buf.len() <2 {
            return None;
        }
        let byte = buf[0];
        if byte == 0x0 {
            // 0x0 -- in the first byte indicates that the length is 0 and token length is 0
            if buf[1] != 0x0 {
                return Some(2)
            } else {
            return None;
            }
        }
        total_bytes_in_packet += 1;
        let len_need_bytes: u8 = match byte >> 4 {
            0..=12 => 0_u8,
            13 => 1_u8,
            14 => 2_u8,
            15 => 4_u8,
            _ => panic!("Protocol violation"),
        };

        total_bytes_in_packet += usize::from(len_need_bytes);
        if len_need_bytes > 0 && buf.len() < total_bytes_in_packet {
            return None
        }

        let remaining_length =
            PacketTcp::parse_length(&mut 0, &buf[0..total_bytes_in_packet]);

        if let Err(_) = remaining_length {
            return None
        }
        let (payload_length, token_length) = remaining_length.unwrap();
        total_bytes_in_packet += 1 + payload_length + token_length;
        if buf.len() < total_bytes_in_packet {
            return None;
        } else {
            return Some(total_bytes_in_packet);
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{
        CoapOption, MessageClass, PacketTcp, RequestType, ResponseType,
    };

    #[test]
    fn test_decode_packet_length_0() {
        let buf = [0x04, 0x01];
        let (length, _) = PacketTcp::parse_length(&mut 0, &buf).unwrap();
        assert_eq!(length, 0);
    }

    #[test]
    fn test_decode_packet_length_less_than_12() {
        let buf = [0xc4];
        let (length, _) = PacketTcp::parse_length(&mut 0, &buf).unwrap();
        assert_eq!(length, 12);
    }

    #[test]
    fn test_decode_packet_length_more_than_12_less_than_255() {
        let buf = [0xd4, 0x33];
        let (length, _) = PacketTcp::parse_length(&mut 0, &buf).unwrap();
        assert_eq!(length, 64);
    }

    #[test]
    fn test_decode_packet_length_more_than_269_less_than_65535() {
        let buf = [0xe4, 0x0e, 0xc8];
        let (length, _) = PacketTcp::parse_length(&mut 0, &buf).unwrap();
        assert_eq!(length, 4053);
    }

    #[test]
    fn test_decode_packet_length_more_than_65535() {
        let buf = [0xf4, 0x00, 0x03, 0x92, 0xf5];
        let (length, _) = PacketTcp::parse_length(&mut 0, &buf).unwrap();
        assert_eq!(length, 300034);
    }

    #[test]
    fn test_decode_packet_with_token() {
        let buf = [0x04, 0x01, 0x51, 0x55, 0x77, 0xe8];
        let packet = PacketTcp::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.code, MessageClass::Request(RequestType::Get));
        assert_eq!(*packet.get_token(), vec![0x51, 0x55, 0x77, 0xE8]);
    }

    #[test]
    fn test_decode_packet_with_options() {
        let buf = [
            0xc4, 0x01, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69, 0x04, 0x54,
            0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31,
        ];
        let packet = PacketTcp::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.code, MessageClass::Request(RequestType::Get));
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
            0x64, 0x45, 0x51, 0x55, 0x77, 0xe8, 0xff, 0x48, 0x65, 0x6c, 0x6c,
            0x6f,
        ];
        let packet = PacketTcp::from_bytes(&buf);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(packet.code, MessageClass::Response(ResponseType::Content));
        assert_eq!(*packet.get_token(), vec![0x51, 0x55, 0x77, 0xE8]);
        assert_eq!(packet.payload, "Hello".as_bytes().to_vec());
    }

    #[test]
    fn test_decode_packet_with_options_and_payload() {
        let buf = [
            0xd4, 0x05, 0x01, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69, 0x04,
            0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31, 0xff, 0x48, 0x65,
            0x6c, 0x6c, 0x6f,
        ];
        let packet = PacketTcp::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.code, MessageClass::Request(RequestType::Get));
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
        assert_eq!(packet.payload, "Hello".as_bytes().to_vec());
    }

    #[test]
    fn test_check_buf_empty_packet() {
        let buf = vec![0;10];
        let check_result = PacketTcp::check_buf(&buf[..]);
        assert!(check_result.is_none());
    }

        #[test]
    fn test_check_buf_packet_length_0() {
        let buf = [0x0, 0x01,0x0,0x0];
        let check_result = PacketTcp::check_buf(&buf);
        assert!(check_result.is_some());
        let check_result = check_result.unwrap();
        assert_eq!(check_result, 2);

                let buf = [0x1, 0x43,0x7f,0x0];
        let check_result = PacketTcp::check_buf(&buf);
        assert!(check_result.is_some());
        let check_result = check_result.unwrap();
        assert_eq!(check_result, 3);
    }

#[test]
    fn test_check_buf_packet_with_token() {
        let buf = [0x04, 0x01, 0x51, 0x55, 0x77, 0xe8, 0x0, 0x0];
        let check_result = PacketTcp::check_buf(&buf);
        assert!(check_result.is_some());
        let check_result = check_result.unwrap();
        assert_eq!(check_result, 6);
    }

    #[test]
    fn test_check_buf_packet_with_options() {
        let buf = [
            0xc4, 0x01, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69, 0x04, 0x54,
            0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31, 0x0, 0x0
        ];
        let check_result = PacketTcp::check_buf(&buf);
        assert!(check_result.is_some());
        let check_result = check_result.unwrap();
        assert_eq!(check_result, 18);
    }

    #[test]
    fn test_check_buf_packet_with_options_and_payload() {
        let mut buf = vec![
            0xd4, 0x05, 0x01, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69, 0x04,
            0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31, 0xff, 0x48, 0x65,
            0x6c, 0x6c, 0x6f,
        ];

        let check_result = PacketTcp::check_buf(&buf[0..buf.len()-2]);
        assert!(check_result.is_none());

        let check_result = PacketTcp::check_buf(&buf[..]);
        assert!(check_result.is_some());
        assert_eq!(check_result.unwrap(), buf.len());

        buf.push(0x01);
        buf.push(0x02);
        let check_result = PacketTcp::check_buf(&buf[..]);
        assert!(check_result.is_some());
        assert_eq!(check_result.unwrap(), buf.len() - 2);
    }

    #[test]
    fn test_decode_packet_with_payload_and_incorrect_length() {
        let buf = [
            0x74, 0x45, 0x51, 0x55, 0x77, 0xe8, 0xff, 0x48, 0x65, 0x6c, 0x6c,
            0x6f,
        ];
        let packet = PacketTcp::from_bytes(&buf);
        assert!(packet.is_err());
    }

    #[test]
    fn test_encode_empty_packet() {
        let mut packet = PacketTcp::new();
        packet.set_code("2.03");
        let bytes = packet.to_bytes();
        assert!(bytes.is_ok());
        assert_eq!(bytes.unwrap(), vec![0x0, 0x43]);
    }

    #[test]
    fn test_encode_empty_packet_with_token() {
        let mut packet = PacketTcp::new();
        packet.set_code("2.03");
        packet.set_token(vec![0x1, 0x2]);
        let bytes = packet.to_bytes();
        assert!(bytes.is_ok());
        assert_eq!(bytes.unwrap(), vec![0x02, 0x43, 0x1, 0x2]);
    }

    #[test]
    fn test_encode_empty_packet_with_token_and_options() {
        let mut packet = PacketTcp::new();

        packet.code = MessageClass::Request(RequestType::Get);

        packet.set_token(vec![0x51, 0x55, 0x77, 0xE8]);
        packet.add_option(CoapOption::UriPath, b"Hi".to_vec());
        packet.add_option(CoapOption::UriPath, b"Test".to_vec());
        packet.add_option(CoapOption::UriQuery, b"a=1".to_vec());
        let bytes = packet.to_bytes();
        assert!(bytes.is_ok());
        assert_eq!(
            bytes.unwrap(),
            vec![
                0xc4, 0x01, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69, 0x04,
                0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31
            ]
        );
    }

    #[test]
    fn test_encode_packet_length() {
        let res = PacketTcp::encode_length(0);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0x0);
        assert_eq!(res.1, vec![]);

        let res = PacketTcp::encode_length(5);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0x5);
        assert_eq!(res.1, vec![]);

        let res = PacketTcp::encode_length(13);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xd);
        assert_eq!(res.1, vec![0x0]);

        let res = PacketTcp::encode_length(26);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xd);
        assert_eq!(res.1, vec![0xd]);

        let res = PacketTcp::encode_length(269);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xe);
        assert_eq!(res.1, vec![0x0, 0x0]);

        let res = PacketTcp::encode_length(512);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xe);
        assert_eq!(res.1, vec![0x0, 0xf3]);

        let res = PacketTcp::encode_length(65805);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xf);
        assert_eq!(res.1, vec![0x0, 0x0, 0x0, 0x0]);

        let res = PacketTcp::encode_length(12423424);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.0, 0xf);
        assert_eq!(res.1, vec![0x0, 0xbc, 0x8f, 0xf3]);
    }

    #[test]
    fn test_encode_packet_with_payload() {
        let mut packet = PacketTcp::new();
        packet.code = MessageClass::Response(ResponseType::Content);
        packet.set_token(vec![0xD0, 0xE2, 0x4D, 0xAC]);
        packet.payload = "Hello".as_bytes().to_vec();
        assert_eq!(
            packet.to_bytes().unwrap(),
            vec![
                0x64, 0x45, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48, 0x65, 0x6C,
                0x6C, 0x6F
            ]
        );
    }

    #[test]
    fn test_encode_decode_content_format() {
        let mut packet = PacketTcp::new();
        packet.set_content_format(ContentFormat::TextPlain);
        assert_eq!(
            ContentFormat::TextPlain,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_without_msb() {
        let mut packet = PacketTcp::new();
        packet.set_content_format(ContentFormat::ApplicationJSON);
        assert_eq!(
            ContentFormat::ApplicationJSON,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_with_msb() {
        let mut packet = PacketTcp::new();
        packet.set_content_format(ContentFormat::ApplicationSensmlXML);
        assert_eq!(
            ContentFormat::ApplicationSensmlXML,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_decode_empty_content_format() {
        let packet = PacketTcp::new();
        assert!(packet.get_content_format().is_none());
    }

    #[test]
    fn options() {
        let mut p = PacketTcp::new();
        p.add_option(CoapOption::UriHost, vec![0]);
        p.add_option(CoapOption::UriPath, vec![1]);
        p.add_option(CoapOption::ETag, vec![2]);
        p.clear_option(CoapOption::ETag);
        assert_eq!(3, p.options().len());

        let bytes = p.to_bytes().unwrap();
        let mut pp = PacketTcp::from_bytes(&bytes).unwrap();
        assert_eq!(2, pp.options().len());

        let mut values = LinkedList::new();
        values.push_back(vec![3]);
        values.push_back(vec![4]);
        pp.set_option(CoapOption::Oscore, values);
        assert_eq!(3, pp.options().len());
    }

    #[test]
    fn observe() {
        let mut p = PacketTcp::new();
        assert_eq!(None, p.get_observe());
        p.set_observe(vec![0]);
        assert_eq!(Some(&vec![0]), p.get_observe());
    }
}
