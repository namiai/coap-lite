use coap_lite::{
    CoapMessageExt, CoapOption, CoapRequest, CoapSignal,
    MessageClass, Packet, PacketTcp, RequestType, SignalType,
};
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::{collections::LinkedList, sync::Mutex, thread, time::Duration};

use rustls;
use rustls::{NoClientAuth, Session};
use std::fs;
use std::io;
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());
    let certs = load_certs("./device.crt");
    let privkey = load_private_key("./device1.key");
    config
        .set_single_cert(certs, privkey)
        .expect("bad certificates/private key");

    let listener = TcpListener::bind("0.0.0.0:5683").unwrap();

    let config = Arc::new(config);
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut tls_session = rustls::ServerSession::new(&config.clone());
        send_csm(&mut tls_session);
        let tls_session = Arc::new(Mutex::new(tls_session));
        let local_tls_session = tls_session.clone();
        thread::spawn(move || loop {
            let mut session = local_tls_session.lock().unwrap();
            send_test_get(&mut *session);
            drop(session);
            thread::sleep(Duration::from_millis(1000));
        });
        thread::spawn(move || {
            loop {
                let mut tls_session = tls_session.lock().unwrap();
                if tls_session.wants_read() {
                    let rc = tls_session.read_tls(&mut stream);
                    if rc.is_err() {
                        let err = rc.unwrap_err();

                        if let io::ErrorKind::WouldBlock = err.kind() {
                            break;
                        }

                        println!("read error {:?}", err);
                        break;
                    }

                    if rc.unwrap() == 0 {
                        println!("eof");
                        break;
                    }

                    // Process newly-received TLS messages.
                    let processed = tls_session.process_new_packets();
                    if processed.is_err() {
                        println!("cannot process packet: {:?}", processed);

                        break;
                    }
                }
                if tls_session.wants_write() {
                    handle_incoming_data(&mut *tls_session);

                    if let Err(err) = tls_session.write_tls(&mut stream) {
                        println!("Error when writing TLS {:?}", err);
                        return;
                    }
                }
                drop(tls_session);
                thread::sleep(Duration::from_millis(10));
            }
        });
    }
    Ok(())
}

fn send_csm(writer: &mut impl Write) {
    let mut csm = PacketTcp::new();
    // set CSM message code
    csm.set_code("7.01");
    let mut max_size = LinkedList::new();
    max_size.push_front(1152_u16.to_be_bytes().to_vec());
    csm.set_option(CoapOption::MaxMessageSize, max_size);
    println!("CSM {:?}", &csm.to_bytes());
    writer.write_all(&csm.to_bytes().unwrap()[..]).unwrap();
}

fn handle_incoming_data(stream: &mut (impl Read + Write)) {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    if buf.len() == 0 {
        return;
    }
    println!("Buf len {}, contents {:?}", buf.len(), buf);

    if let Ok(parsed_packet) = PacketTcp::from_bytes(&buf[..]) {
        println!("Parsed packet type {}", parsed_packet.get_code());
        let payload = parsed_packet.get_payload();
        if payload.len() > 0 {
            println!(
                "Payload: {}",
                String::from_utf8(payload.to_owned())
                    .unwrap_or("Error decoding the payload".to_owned())
            )
        }
        let options = parsed_packet.options();
        if options.len() > 0 {
            println!("Options:");
            for option in options {
                let option_value = option
                    .1
                    .iter()
                    .map(|opt| {
                        String::from_utf8(opt.to_owned()).unwrap_or_default()
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                println!(
                    "   {}: {}, raw: {:x?}",
                    option.0, option_value, option.1
                );
            }
        }
        match parsed_packet.get_message_class() {
            MessageClass::Signaling(SignalType::Ping) => send_pong(stream, parsed_packet.get_token().to_owned()),
            _ => return,
        }
    }
}

fn send_pong(stream: &mut impl Write, token: Vec<u8>) {
    println!("Sending Pong");
    let reply = CoapSignal::new(SignalType::Pong, token);
    stream.write_all(&reply.to_bytes().unwrap()[..]).unwrap();
}

fn send_test_get(stream: &mut impl Write) {
    let mut request: CoapRequest<PacketTcp> =
        CoapRequest::new(RequestType::Get);
    request.set_path("/motion");
    stream.write_all(&request.to_bytes().unwrap()[..]).unwrap();
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile =
        fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile =
        fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)
            .expect("cannot parse private key .pem file")
        {
            Some(rustls_pemfile::Item::RSAKey(key)) => {
                return rustls::PrivateKey(key)
            }
            Some(rustls_pemfile::Item::PKCS8Key(key)) => {
                return rustls::PrivateKey(key)
            }
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}
