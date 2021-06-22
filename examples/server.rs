use coap_lite::{CoapRequest, ObserveOption, Packet, PacketUdp};
use rand::prelude::*;
use serde_json::json;
use std::{
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
        let request: CoapRequest<SocketAddr, PacketUdp> =
            CoapRequest::from_packet(packet, src);

        let method = request.get_method().clone();
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

        let mut response = request.response.unwrap();
        response.message.set_payload(payload);
        response.set_observe_flag(ObserveOption::Register);
        let packet = response.message.to_bytes().unwrap();
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
            "motion_detected": motion_stat < 20,
            "rssi": rng.gen_range(-95..-45)
        }
    })
    .to_string()
}

fn register_address_for_observe(
    socket: UdpSocket,
    src: SocketAddr,
    request: CoapRequest<SocketAddr, PacketUdp>,
) {
    let start_time = chrono::Utc::now();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1000));
        let local_request = request.clone();
        let mut response = local_request.response.unwrap();
        response.message.set_observe(generate_observe_value());
        response
            .message
            .set_payload(generate_motion_stat().as_bytes().into());
        let packet = response.message.to_bytes().unwrap();
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
