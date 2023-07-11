use alloc::{
    collections::{BTreeMap, LinkedList},
    vec::Vec,
};
use core::convert::TryFrom;
use std::fmt::{Display, Error, Formatter};

use crate::{MessageClass, MessageType, error::{InvalidContentFormat, InvalidObserve, MessageError}};

macro_rules! u8_to_unsigned_be {
    ($src:ident, $start:expr, $end:expr, $t:ty) => ({
        (0..=$end - $start).rev().fold(
            0, |acc, i| acc | $src[$start+i] as $t << i * 8
        )
    })
}

/// The CoAP options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoapOption {
    IfMatch,
    UriHost,
    ETag,
    IfNoneMatch,
    Observe,
    UriPort,
    LocationPath,
    Oscore,
    UriPath,
    ContentFormat,
    MaxAge,
    UriQuery,
    Accept,
    LocationQuery,
    Block2,
    Block1,
    ProxyUri,
    ProxyScheme,
    Size1,
    Size2,
    NoResponse,
    MaxMessageSize,
    RequestTag,
    Unknown(u16),
}

impl Display for CoapOption {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            CoapOption::IfMatch => write!(f, "If-Match"),
            CoapOption::UriHost => write!(f, "Uri-Host"),
            CoapOption::ETag => write!(f, "ETag"),
            CoapOption::IfNoneMatch => write!(f, "If-None-Match"),
            CoapOption::Observe => write!(f, "Observe"),
            CoapOption::UriPort => write!(f, "Uri-Port"),
            CoapOption::LocationPath => write!(f, "Location-Path"),
            CoapOption::Oscore => write!(f, "OSCORE"),
            CoapOption::UriPath => write!(f, "Uri-Path"),
            CoapOption::ContentFormat => write!(f, "Content-Format"),
            CoapOption::MaxAge => write!(f, "Max-Age"),
            CoapOption::UriQuery => write!(f, "Uri-Query"),
            CoapOption::Accept => write!(f, "Accept"),
            CoapOption::LocationQuery => write!(f, "Location-Query"),
            CoapOption::Block1 => write!(f, "Block1"),
            CoapOption::Block2 => write!(f, "Block2"),
            CoapOption::ProxyUri => write!(f, "Proxy-Uri"),
            CoapOption::ProxyScheme => write!(f, "Proxy-Scheme"),
            CoapOption::Size1 => write!(f, "Size1"),
            CoapOption::Size2 => write!(f, "Size2"),
            CoapOption::NoResponse => write!(f, "No-Response"),
            CoapOption::MaxMessageSize => write!(f, "Max-Message-Size"),
            CoapOption::RequestTag => write!(f, "Request-Tag"),
            CoapOption::Unknown(c) => write!(f, "Unknown - {}", c),
        }
    }
}

impl From<u16> for CoapOption {
    fn from(number: u16) -> CoapOption {
        match number {
            1 => CoapOption::IfMatch,
            2 => CoapOption::MaxMessageSize,
            3 => CoapOption::UriHost,
            4 => CoapOption::ETag,
            5 => CoapOption::IfNoneMatch,
            6 => CoapOption::Observe,
            7 => CoapOption::UriPort,
            8 => CoapOption::LocationPath,
            9 => CoapOption::Oscore,
            11 => CoapOption::UriPath,
            12 => CoapOption::ContentFormat,
            14 => CoapOption::MaxAge,
            15 => CoapOption::UriQuery,
            17 => CoapOption::Accept,
            20 => CoapOption::LocationQuery,
            23 => CoapOption::Block2,
            27 => CoapOption::Block1,
            35 => CoapOption::ProxyUri,
            39 => CoapOption::ProxyScheme,
            60 => CoapOption::Size1,
            28 => CoapOption::Size2,
            258 => CoapOption::NoResponse,
            292 => CoapOption::NoResponse,
            _ => CoapOption::Unknown(number),
        }
    }
}

impl From<&CoapOption> for u16 {
    fn from(option: &CoapOption) -> u16 {
        match option {
            CoapOption::IfMatch => 1,
            CoapOption::MaxMessageSize => 2,
            CoapOption::UriHost => 3,
            CoapOption::ETag => 4,
            CoapOption::IfNoneMatch => 5,
            CoapOption::Observe => 6,
            CoapOption::UriPort => 7,
            CoapOption::LocationPath => 8,
            CoapOption::Oscore => 9,
            CoapOption::UriPath => 11,
            CoapOption::ContentFormat => 12,
            CoapOption::MaxAge => 14,
            CoapOption::UriQuery => 15,
            CoapOption::Accept => 17,
            CoapOption::LocationQuery => 20,
            CoapOption::Block2 => 23,
            CoapOption::Block1 => 27,
            CoapOption::ProxyUri => 35,
            CoapOption::ProxyScheme => 39,
            CoapOption::Size1 => 60,
            CoapOption::Size2 => 28,
            CoapOption::NoResponse => 258,
            CoapOption::RequestTag => 292,
            CoapOption::Unknown(number) => *number,
        }
    }
}

/// The content formats.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentFormat {
    TextPlain,
    ApplicationLinkFormat,
    ApplicationXML,
    ApplicationOctetStream,
    ApplicationEXI,
    ApplicationJSON,
    ApplicationCBOR,
    ApplicationSenmlJSON,
    ApplicationSensmlJSON,
    ApplicationSenmlCBOR,
    ApplicationSensmlCBOR,
    ApplicationSenmlExi,
    ApplicationSensmlExi,
    ApplicationSenmlXML,
    ApplicationSensmlXML,
}

impl TryFrom<usize> for ContentFormat {
    type Error = InvalidContentFormat;

    fn try_from(number: usize) -> Result<ContentFormat, InvalidContentFormat> {
        match number {
            0 => Ok(ContentFormat::TextPlain),
            40 => Ok(ContentFormat::ApplicationLinkFormat),
            41 => Ok(ContentFormat::ApplicationXML),
            42 => Ok(ContentFormat::ApplicationOctetStream),
            47 => Ok(ContentFormat::ApplicationEXI),
            50 => Ok(ContentFormat::ApplicationJSON),
            60 => Ok(ContentFormat::ApplicationCBOR),
            110 => Ok(ContentFormat::ApplicationSenmlJSON),
            111 => Ok(ContentFormat::ApplicationSensmlJSON),
            112 => Ok(ContentFormat::ApplicationSenmlCBOR),

            113 => Ok(ContentFormat::ApplicationSensmlCBOR),
            114 => Ok(ContentFormat::ApplicationSenmlExi),
            115 => Ok(ContentFormat::ApplicationSensmlExi),
            310 => Ok(ContentFormat::ApplicationSenmlXML),
            311 => Ok(ContentFormat::ApplicationSensmlXML),
            _ => Err(InvalidContentFormat),
        }
    }
}

impl From<ContentFormat> for usize {
    fn from(format: ContentFormat) -> usize {
        match format {
            ContentFormat::TextPlain => 0,
            ContentFormat::ApplicationLinkFormat => 40,
            ContentFormat::ApplicationXML => 41,
            ContentFormat::ApplicationOctetStream => 42,
            ContentFormat::ApplicationEXI => 47,
            ContentFormat::ApplicationJSON => 50,
            ContentFormat::ApplicationCBOR => 60,
            ContentFormat::ApplicationSenmlJSON => 110,
            ContentFormat::ApplicationSensmlJSON => 111,
            ContentFormat::ApplicationSenmlCBOR => 112,
            ContentFormat::ApplicationSensmlCBOR => 113,
            ContentFormat::ApplicationSenmlExi => 114,
            ContentFormat::ApplicationSensmlExi => 115,
            ContentFormat::ApplicationSenmlXML => 310,
            ContentFormat::ApplicationSensmlXML => 311,
        }
    }
}

/// The values of the observe option.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObserveOption {
    Register,
    Deregister,
}

impl TryFrom<usize> for ObserveOption {
    type Error = InvalidObserve;

    fn try_from(number: usize) -> Result<ObserveOption, InvalidObserve> {
        match number {
            0 => Ok(ObserveOption::Register),
            1 => Ok(ObserveOption::Deregister),
            _ => Err(InvalidObserve),
        }
    }
}

impl From<ObserveOption> for usize {
    fn from(observe: ObserveOption) -> usize {
        match observe {
            ObserveOption::Register => 0,
            ObserveOption::Deregister => 1,
        }
    }
}

/// An iterator over the options of a packet.
pub type Options =
    alloc::collections::btree_map::BTreeMap<CoapOption, LinkedList<Vec<u8>>>;

pub type OptionsIter<'a> =
    alloc::collections::btree_map::Iter<'a, CoapOption, LinkedList<Vec<u8>>>;

pub trait Packet: Sized {
    fn new() -> Self;
    fn options(&self) -> OptionsIter<'_>;
    fn set_token(&mut self, token: Vec<u8>);
    fn get_token(&self) -> &Vec<u8>;
    fn set_option(&mut self, tp: CoapOption, value: LinkedList<Vec<u8>>);
    fn get_option(&self, tp: CoapOption) -> Option<&LinkedList<Vec<u8>>>;
    fn add_option(&mut self, tp: CoapOption, value: Vec<u8>);
    fn clear_option(&mut self, tp: CoapOption);
    fn set_content_format(&mut self, cf: ContentFormat);
    fn get_content_format(&self) -> Option<ContentFormat>;
    fn set_observe(&mut self, value: Vec<u8>);
    fn get_observe(&self) -> Option<&Vec<u8>>;
    fn from_bytes(buf: &[u8]) -> Result<Self, MessageError>;
    fn to_bytes(&self) -> Result<Vec<u8>, MessageError>;
    fn set_code(&mut self, code: &str);
    fn get_code(&self) -> String;
    fn set_code_from_message_class(&mut self, message_class: MessageClass);
    fn get_message_class(&self) -> MessageClass;
    fn set_type(&mut self, message_type: MessageType);
    fn set_type_from_request(
        &mut self,
        request_message_type: Option<MessageType>,
    ) -> Result<(), MessageError>;
    fn get_type(&self) -> Option<MessageType>;
    fn set_message_id(&mut self, message_id: u16);
    fn get_message_id(&self) -> Option<u16>;
    fn set_payload(&mut self, payload: Vec<u8>);
    fn get_payload(&self) -> &Vec<u8>;

    fn set_path(&mut self, path: &str) {
        self.clear_option(CoapOption::UriPath);

        let segs = path.split('/');
        for (i, s) in segs.enumerate() {
            if i == 0 && s.is_empty() {
                continue;
            }

            self.add_option(CoapOption::UriPath, s.as_bytes().to_vec());
        }
    }
    fn get_path(&self) -> String {
        match self.get_option(CoapOption::UriPath) {
            Some(options) => {
                let mut vec = Vec::new();
                for option in options.iter() {
                    if let Ok(seg) = core::str::from_utf8(option) {
                        vec.push(seg);
                    }
                }
                vec.join("/")
            }
            _ => "".to_string(),
        }
    }
}

pub fn decode_options(
    idx: &mut usize,
    buf: &[u8],
) -> Result<Options, MessageError> {
    let mut options_number = 0;
    let mut options: BTreeMap<CoapOption, LinkedList<Vec<u8>>> =
        BTreeMap::new();
    while *idx < buf.len() {
        let byte = buf[*idx];

        if byte == 255 || *idx > buf.len() {
            break;
        }

        let mut delta = (byte >> 4) as u16;
        let mut length = (byte & 0xF) as usize;

        *idx += 1;

        // Check for special delta characters
        match delta {
            13 => {
                if *idx >= buf.len() {
                    return Err(MessageError::InvalidOptionLength);
                }
                delta = (buf[*idx] + 13).into();
                *idx += 1;
            }
            14 => {
                if *idx + 1 >= buf.len() {
                    return Err(MessageError::InvalidOptionLength);
                }

                delta =
                    u16::from_be(u8_to_unsigned_be!(buf, *idx, *idx + 1, u16))
                        + 269;
                *idx += 2;
            }
            15 => {
                return Err(MessageError::InvalidOptionDelta);
            }
            _ => {}
        };

        // Check for special length characters
        match length {
            13 => {
                if *idx >= buf.len() {
                    return Err(MessageError::InvalidOptionLength);
                }

                length = buf[*idx] as usize + 13;
                *idx += 1;
            }
            14 => {
                if *idx + 1 >= buf.len() {
                    return Err(MessageError::InvalidOptionLength);
                }

                length = (u16::from_be(u8_to_unsigned_be!(
                    buf,
                    *idx,
                    *idx + 1,
                    u16
                )) + 269) as usize;
                *idx += 2;
            }
            15 => {
                return Err(MessageError::InvalidOptionLength);
            }
            _ => {}
        };

        options_number += delta;

        let end = *idx + length;
        if end > buf.len() {
            return Err(MessageError::InvalidOptionLength);
        }
        let options_value = buf[*idx..end].to_vec();

        options
            .entry(CoapOption::from(options_number))
            .or_insert_with(LinkedList::new)
            .push_back(options_value);

        *idx += length;
    }
    Ok(options)
}

pub fn encode_options(options: &Options) -> Vec<u8> {
    let mut options_delta_length = 0;
    let mut options_bytes: Vec<u8> = Vec::new();
    for (number, value_list) in options {
        for value in value_list.iter() {
            let mut header: Vec<u8> = Vec::with_capacity(1 + 2 + 2);
            let delta = u16::from(number) - options_delta_length;

            let mut byte: u8 = 0;
            if delta <= 12 {
                byte |= (delta << 4) as u8;
            } else if delta < 269 {
                byte |= 13 << 4;
            } else {
                byte |= 14 << 4;
            }
            if value.len() <= 12 {
                byte |= value.len() as u8;
            } else if value.len() < 269 {
                byte |= 13;
            } else {
                byte |= 14;
            }
            header.push(byte);

            if delta > 12 && delta < 269 {
                header.push((delta - 13) as u8);
            } else if delta >= 269 {
                let fix = (delta - 269) as u16;
                header.push((fix >> 8) as u8);
                header.push((fix & 0xFF) as u8);
            }

            if value.len() > 12 && value.len() < 269 {
                header.push((value.len() - 13) as u8);
            } else if value.len() >= 269 {
                let fix = (value.len() - 269) as u16;
                header.push((fix >> 8) as u8);
                header.push((fix & 0xFF) as u8);
            }

            options_delta_length += delta;

            options_bytes.reserve(header.len() + value.len());
            options_bytes.append(&mut header);
            options_bytes.extend_from_slice(&value);
        }
    }
    options_bytes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn option() {
        for i in 0..512 {
            match CoapOption::try_from(i) {
                Ok(o) => assert_eq!(i, (&o).into()),
                _ => (),
            }
        }
    }

    #[test]
    fn content_format() {
        for i in 0..512 {
            match ContentFormat::try_from(i) {
                Ok(o) => assert_eq!(i, o.into()),
                _ => (),
            }
        }
    }

    use super::super::packet::ObserveOption;
    #[test]
    fn observe_option() {
        for i in 0..8 {
            match ObserveOption::try_from(i) {
                Ok(o) => assert_eq!(i, o.into()),
                _ => (),
            }
        }
    }
}
