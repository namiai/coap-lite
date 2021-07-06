use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::convert::TryFrom;

use crate::{error::MessageError, MessageClass, MessageType};

/// The raw byte header representation, useful for encoding/decoding directly.
#[derive(Debug, Clone)]
pub struct HeaderRaw {
    ver_type_tkl: u8,
    code: u8,
    message_id: u16,
}

impl HeaderRaw {
    /// Writes the header into the given buffer, which must have a capacity of
    /// at least 4.
    pub fn serialize_into(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<(), MessageError> {
        if buf.capacity() < 4 {
            return Err(MessageError::InvalidPacketLength);
        }

        buf.push(self.ver_type_tkl);
        buf.push(self.code);
        let id_bytes = self.message_id.to_be_bytes();
        buf.extend(&id_bytes);

        Ok(())
    }
}

impl Default for HeaderRaw {
    fn default() -> HeaderRaw {
        HeaderRaw {
            ver_type_tkl: 0x40, // version: 1, type: Confirmable, TKL: 0
            code: 0x01,         // GET
            message_id: 0,
        }
    }
}

impl TryFrom<&[u8]> for HeaderRaw {
    type Error = MessageError;

    fn try_from(buf: &[u8]) -> Result<HeaderRaw, MessageError> {
        if buf.len() < 4 {
            return Err(MessageError::InvalidPacketLength);
        }

        let mut id_bytes = [0; 2];
        id_bytes.copy_from_slice(&buf[2..4]);

        Ok(HeaderRaw {
            ver_type_tkl: buf[0],
            code: buf[1],
            message_id: u16::from_be_bytes(id_bytes),
        })
    }
}

/// The message header.
#[derive(Debug, Clone)]
pub struct Header {
    ver_type_tkl: u8,
    pub code: MessageClass,
    pub message_id: u16,
}

impl Default for Header {
    fn default() -> Header {
        Header::from_raw(&HeaderRaw::default())
    }
}

impl Header {
    /// Creates a new header.
    pub fn new() -> Header {
        Default::default()
    }

    /// Creates a new header from a raw header.
    pub fn from_raw(raw: &HeaderRaw) -> Header {
        Header {
            ver_type_tkl: raw.ver_type_tkl,
            code: raw.code.into(),
            message_id: raw.message_id,
        }
    }

    /// Returns the raw header.
    pub fn to_raw(&self) -> HeaderRaw {
        HeaderRaw {
            ver_type_tkl: self.ver_type_tkl,
            code: self.code.into(),
            message_id: self.message_id,
        }
    }

    /// Sets the version.
    #[inline]
    pub fn set_version(&mut self, v: u8) {
        let type_tkl = 0x3F & self.ver_type_tkl;
        self.ver_type_tkl = v << 6 | type_tkl;
    }

    /// Returns the version.
    #[inline]
    pub fn get_version(&self) -> u8 {
        self.ver_type_tkl >> 6
    }

    /// Sets the message type.
    #[inline]
    pub fn set_type(&mut self, t: MessageType) {
        let tn = match t {
            MessageType::Confirmable => 0,
            MessageType::NonConfirmable => 1,
            MessageType::Acknowledgement => 2,
            MessageType::Reset => 3,
        };

        let ver_tkl = 0xCF & self.ver_type_tkl;
        self.ver_type_tkl = tn << 4 | ver_tkl;
    }

    /// Returns the message type.
    #[inline]
    pub fn get_type(&self) -> MessageType {
        let tn = (0x30 & self.ver_type_tkl) >> 4;
        match tn {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            3 => MessageType::Reset,
            _ => unreachable!(),
        }
    }

    /// Sets the token length.
    #[inline]
    pub fn set_token_length(&mut self, tkl: u8) {
        assert_eq!(0xF0 & tkl, 0);

        let ver_type = 0xF0 & self.ver_type_tkl;
        self.ver_type_tkl = tkl | ver_type;
    }

    /// Returns the token length.
    #[inline]
    pub fn get_token_length(&self) -> u8 {
        0x0F & self.ver_type_tkl
    }

    /// Sets the message code from a string.
    pub fn set_code(&mut self, code: &str) {
        let code_vec: Vec<&str> = code.split('.').collect();
        assert_eq!(code_vec.len(), 2);

        let class_code = code_vec[0].parse::<u8>().unwrap();
        let detail_code = code_vec[1].parse::<u8>().unwrap();
        assert_eq!(0xF8 & class_code, 0);
        assert_eq!(0xE0 & detail_code, 0);

        self.code = (class_code << 5 | detail_code).into();
    }

    /// Returns the message code as a string.
    pub fn get_code(&self) -> String {
        self.code.to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header_codes() {
        for code in 0..255 {
            let class: MessageClass = code.into();
            let code_str = class.to_string();

            let mut header = Header::new();
            header.set_code(&code_str);

            // Reserved class could technically be many codes, so only check
            // valid items
            if class != MessageClass::Reserved {
                assert_eq!(u8::from(class), code);
                assert_eq!(class, header.code);
                assert_eq!(code_str, header.get_code());
            }
        }
    }

    #[test]
    fn serialize_raw_fail() {
        let h = HeaderRaw::default();
        let mut buf = Vec::with_capacity(3);
        assert_eq!(
            MessageError::InvalidPacketLength,
            h.serialize_into(&mut buf).unwrap_err()
        );
    }

    #[test]
    fn from_bytes_fail() {
        let b: &[u8] = &[1, 2, 3];
        assert_eq!(
            MessageError::InvalidPacketLength,
            HeaderRaw::try_from(b).unwrap_err()
        );
    }

    #[test]
    fn types() {
        let mut h = Header::new();
        h.set_type(MessageType::Acknowledgement);
        assert_eq!(MessageType::Acknowledgement, h.get_type());
        h.set_type(MessageType::Confirmable);
        assert_eq!(MessageType::Confirmable, h.get_type());
        h.set_type(MessageType::NonConfirmable);
        assert_eq!(MessageType::NonConfirmable, h.get_type());
        h.set_type(MessageType::Reset);
        assert_eq!(MessageType::Reset, h.get_type());
    }
}
