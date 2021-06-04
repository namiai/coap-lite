use coap_lite::{CoapRequest, Packet, PacketUdp};
use std::net::{SocketAddr, UdpSocket};

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();
    let mut buf = [0; 100];
    let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");

    println!("Payload {:x?}", &buf[..size]);

    let packet = Packet::from_bytes(&buf[..size]).unwrap();
    let request:CoapRequest<SocketAddr, PacketUdp> = CoapRequest::from_packet(packet, src);

    let method = request.get_method().clone();
    let path = request.get_path();

    println!("Received CoAP request '{:?} {}' from {}", method, path, src);

    let mut response = request.response.unwrap();
    response.message.set_payload(b"OK".to_vec());

    let packet = response.message.to_bytes().unwrap();
    socket
        .send_to(&packet[..], &src)
        .expect("Could not send the data");
}
