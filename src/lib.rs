//! A lightweight low-level CoAP message manipulation crate.
//!
//! Its goal is to be compliant with the CoAP standards and to provide a
//! building block for libraries (e.g.
//! [coap](https://github.com/Covertness/coap-rs)) and applications.
//!
//! `coap-lite` supports `#![no_std]` and embedded environments.
//!
//! It was originally based on the improved low-level message handling code
//! from the [coap] crate as well as [rust-async-coap], made to work in bare
//! metal environments.
//!
//! ## Supported RFCs
//!
//! - CoAP [RFC 7252](https://tools.ietf.org/html/rfc7252)
//! - CoAP Observe Option [RFC 7641](https://tools.ietf.org/html/rfc7641)
//! - Too Many Requests Response Code [RFC 8516](https://tools.ietf.org/html/rfc8516)
//! - Constrained RESTful Environments (CoRE) Link Format
//!   [RFC6690](https://tools.ietf.org/html/rfc6690#:~:text=well-known%2Fcore)
//!
//! ## Usage
//!
//! This crate provides several types that can be used to build, modify and
//! encode/decode CoAP messages to/from their byte representation.
//!
//! **Note for no_std users**: it does require allocation, so you might have to
//! set a global allocator depending on your target.
//!
//! ### Client
//!
//! The following example uses `std::net::UdpSocket` to send the UDP packet but
//! you can use anything, e.g. [smoltcp](https://github.com/smoltcp-rs/smoltcp)
//! for embedded.
//!
//! ```rust
//! use coap_lite::{
//!     CoapRequest, RequestType as Method
//! };
//! use std::net::{SocketAddr, UdpSocket};
//!
//! fn main() {
//!     let mut request: CoapRequest<SocketAddr> = CoapRequest::new();
//!
//!     request.set_method(Method::Get);
//!     request.set_path("/test");
//!
//!     let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
//!
//!     let packet = request.message.to_bytes().unwrap();
//!     socket.send_to(&packet[..], "127.0.0.1:5683").expect("Could not send the data");
//! }
//! ```
//!
//! ### Server
//!
//! ```rust
//! use coap_lite::{CoapRequest, Packet};
//! use std::net::{UdpSocket};
//!
//! fn main() {
//!     let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();
//!     let mut buf = [0; 100];
//!     let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
//!
//!     println!("Payload {:x?}", &buf[..size]);
//!
//!     let packet = Packet::from_bytes(&buf[..size]).unwrap();
//!     let request = CoapRequest::from_packet(packet, src);
//!
//!     let method = request.get_method().clone();
//!     let path = request.get_path();
//!
//!     println!("Received CoAP request '{:?} {}' from {}", method, path, src);
//!
//!     let mut response = request.response.unwrap();
//!     response.message.payload = b"OK".to_vec();
//!
//!     let packet = response.message.to_bytes().unwrap();
//!     socket.send_to(&packet[..], &src).expect("Could not send the data");
//! }
//! ```
//!
//! ### Low-level binary conversion
//!
//! ```rust
//! use coap_lite::{
//!     CoapOption, MessageClass, MessageType,
//!     Packet, RequestType, ResponseType,
//! };
//!
//! let mut request = Packet::new();
//! request.header.message_id = 23839;
//! request.header.code = MessageClass::Request(RequestType::Get);
//! request.set_token(vec![0, 0, 57, 116]);
//! request.add_option(CoapOption::UriHost, b"localhost".to_vec());
//! request.add_option(CoapOption::UriPath, b"tv1".to_vec());
//! assert_eq!(
//!     [
//!         0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
//!         0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
//!     ],
//!     request.to_bytes().unwrap()[..]
//! );
//!
//! let response = Packet::from_bytes(&[
//!     0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65,
//!     0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
//! ])
//! .unwrap();
//! assert_eq!(23839, response.header.message_id);
//! assert_eq!(
//!     MessageClass::Response(ResponseType::Content),
//!     response.header.code
//! );
//! assert_eq!(MessageType::Acknowledgement, response.header.get_type());
//! assert_eq!([0, 0, 57, 116], response.get_token()[..]);
//! assert_eq!(b"Hello World!", &response.payload[..]);
//! ```
//!
//! [coap]: https://github.com/covertness/coap-rs
//! [rust-async-coap]: https://github.com/google/rust-async-coap

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_doctest_main)]

#[macro_use]
extern crate alloc;

#[cfg_attr(tarpaulin, skip)]
pub mod error;

pub mod link_format;
mod message_class;
mod message_type;
mod observe;
mod packet;
mod request;
mod request_type;
mod response;
mod response_type;
mod signal_type;
mod tcp;
mod udp;

#[cfg(feature = "with-coap-message")]
mod impl_coap_message;

use std::io::Read;

pub use error::MessageError;
pub use message_class::MessageClass;
pub use message_type::MessageType;
pub use observe::Subject;
pub use packet::{CoapOption, ContentFormat, ObserveOption, Packet};
pub use request::CoapRequest;
pub use request_type::RequestType;
pub use response::CoapResponse;
pub use response_type::ResponseType;
pub use signal_type::SignalType;
pub use tcp::packet::PacketTcp;
pub use udp::header::{Header, HeaderRaw};
pub use udp::packet::PacketUdp;

pub fn parse_from_stream(
    reader: &mut dyn Read,
) -> Result<PacketTcp, MessageError> {
    let mut packet_buf = vec![0; 1];
    reader.read_exact(&mut packet_buf).unwrap();
    let byte = packet_buf[0];
    let len_need_bytes: u8 = match byte >> 4 {
        0..=12 => 0_u8,
        13 => 1_u8,
        14 => 2_u8,
        15 => 4_u8,
        _ => panic!("Protocol violation"),
    };

    packet_buf.resize(1 + usize::from(len_need_bytes), 0);
    if len_need_bytes > 0 {
        reader.read_exact(&mut packet_buf[1..]).unwrap();
    }
    let (payload_length, token_length) =
        PacketTcp::parse_length(&mut 0, packet_buf.as_slice()).unwrap();

    let header_length: usize = 1_usize + usize::from(len_need_bytes);

    let packet_length: usize =
        header_length + 1_usize + token_length + payload_length;

    packet_buf.resize(packet_length, 0);
    reader.read_exact(&mut packet_buf[header_length..]).unwrap();
    println!("Incoming bytes {:?}", packet_buf);
    PacketTcp::from_bytes(&packet_buf[..])
}
