use chrono::Utc;
use coap_lite::{
    parse_from_stream, CoapRequest, ObserveOption, Packet, PacketTcp,
    RequestType as Method,
};
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};

use std::io::{stdout, Read, Write};
use std::sync::Arc;

use rustls;
use webpki;
use webpki_roots;

use rustls::Session;

fn main() {
    let mut config = rustls::ClientConfig::with_ciphersuites(&[
        &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
    ]);
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect("google.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();

    let mut request: CoapRequest<SocketAddr, PacketTcp> = CoapRequest::new();

    request.set_method(Method::Get);
    request.set_path("/test");
    request.message.set_token(vec![0x7d, 0x34]);
    request
        .message
        .set_observe(vec![ObserveOption::Register as u8]);
    let current_time = Utc::now().to_rfc2822();
    request
        .message
        .set_payload(current_time.as_bytes().to_vec());
    let mut stream = TcpStream::connect("127.0.0.1:5683").unwrap();

    let packet = request.message.to_bytes().unwrap();
    println!("Packet {:?}", packet);
    stream.write(&packet[..]).expect("Could not send the data");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut buf = [0; 1];
        if let Ok(p) = stream.peek(&mut buf) {
            if p > 0 {
                if let Ok(packet) = parse_from_stream(&mut reader) {
                    let payload_str =
                        String::from_utf8(packet.get_payload().to_vec())
                            .unwrap();
                    println!(
                        "Incoming packet with payload {} and token {:?}",
                        payload_str,
                        packet.get_token()
                    );
                }
            }
        }
    }
}
