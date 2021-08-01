use coap_lite::{
    CoapMessageExt, CoapRequest, CoapResponse, ObserveOption, Packet,
    PacketUdp, ResponseType,
};
use rand::prelude::*;
use serde_json::json;
use std::{
    collections::LinkedList,
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:5683").unwrap();
    loop {
        let mut buf = [0; 100];
        let (size, src) =
            socket.recv_from(&mut buf).expect("Didn't receive data");

        println!("Payload {:x?}", &buf[..size]);

        let packet = PacketUdp::from_bytes(&buf[..size]).unwrap();
        let request: CoapRequest<PacketUdp> =
            CoapRequest::from_packet(packet).unwrap();

        let method = request.get_request_type();
        let path = request.get_path();
        let observe_flag = request.get_observe_flag();

        println!(
            "Received CoAP request '{:x?} {}' from {}",
            method, path, src
        );

        let payload = match &path[..] {
            "motion" => {
                if let Some(flag) = observe_flag {
                    if flag == ObserveOption::Register {
                        register_address_for_observe(
                            socket
                                .try_clone()
                                .expect("Cannot clone the socket"),
                            src.clone(),
                            request.clone(),
                        )
                    }
                }
                generate_motion_stat().as_bytes().to_vec()
            }
            _ => b"OK".to_vec(),
        };

        let mut response: CoapResponse<PacketUdp> =
            CoapResponse::from_request(&request, ResponseType::Content)
                .unwrap();
        response.set_payload(payload);
        response.set_observe_value(generate_observe_value());
        let packet = response.to_bytes().unwrap();
        socket
            .send_to(&packet[..], &src)
            .expect("Could not send the data");
    }
}

fn generate_motion_stat() -> String {
    let mut rng = thread_rng();
    let motion_stat = rng.gen_range(0..100);

    json!({
        "a8bb5001020a": {
            "statistics":motion_stat,
            "motion_detected": motion_stat > 70,
            "rssi": rng.gen_range(-95..-45)
        }
    })
    .to_string()
}

fn register_address_for_observe(
    socket: UdpSocket,
    src: SocketAddr,
    request: CoapRequest<PacketUdp>,
) {
    let start_time = chrono::Utc::now();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1000));
        let mut response =
            CoapResponse::from_request(&request, ResponseType::Content)
                .unwrap();
        response.set_observe_value(generate_observe_value());
        response.set_payload(generate_motion_stat().as_bytes().into());
        let mut etag_option: LinkedList<Vec<u8>> = LinkedList::new();
        etag_option
            .push_front(chrono::Utc::now().timestamp().to_be_bytes().to_vec());
        response.set_option(coap_lite::CoapOption::ETag, etag_option);
        let packet = response.to_bytes().unwrap();
        if let Err(_) = socket.send_to(&packet[..], src) {
            break;
        }
        if chrono::Utc::now().timestamp() - start_time.timestamp() > 60 {
            println!("Timeout reached, stopping notifications");
            break;
        }
    });
}

fn generate_observe_value() -> Vec<u8> {
    let timestamp_bytes =
        chrono::Local::now().timestamp_millis().to_be_bytes();
    timestamp_bytes[timestamp_bytes.len() - 3..].to_vec()
}
