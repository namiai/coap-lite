use coap_lite::{CoapMessageExt, CoapRequest, CoapResponse, ObserveOption, Packet, PacketUdp, RequestType};
use std::net::{SocketAddr, UdpSocket};

fn main() {
    let mut request: CoapRequest<PacketUdp> = CoapRequest::new(RequestType::Get);

    request.set_path("/motion");
    request.message.set_token(vec![0x01]);
    request.message.set_message_id(0x01);
    request
        .message
        .set_type(coap_lite::MessageType::NonConfirmable);
    request.set_observe_flag(ObserveOption::Register);

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

    let packet = request.message.to_bytes().unwrap();
    socket
        .send_to(&packet[..], "127.0.0.1:5683")
        .expect("Could not send the data");

    loop {
        let mut buf = [0; 100];
        let (size, src) =
            socket.recv_from(&mut buf).expect("Didn't receive data");

        println!("Payload {:x?}", &buf[..size]);

        let packet = PacketUdp::from_bytes(&buf[..size]).unwrap();

        let request = CoapRequest::from_packet(packet).unwrap();
        let method = request.get_request_type();
        let token = request.get_token();
        let payload = request.get_payload();
        println!("Received CoAP request '{:x?}' token {:x?} from {} with payload {}", method, token, src, String::from_utf8(payload.to_vec()).unwrap());
    }
}
