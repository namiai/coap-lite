use argh::FromArgs;
use coap_lite::{ObserveOption, ResponseType};
use coap_lite::{
    CoapOption, CoapRequest, CoapResponse, MessageClass, Packet, PacketTcp,
    SignalType, CoapMessageExt, CoapSignal
};
use core::fmt;
use rand::prelude::*;
use serde_json::json;
use std::collections::LinkedList;
use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::*;
use tokio::time::sleep;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::{client::TlsStream, TlsConnector};

#[macro_use]
extern crate log;

#[derive(FromArgs)]
/// CoAP server with TCP, TLS and Async
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// CA cert file
    #[argh(option, short = 'C')]
    ca: PathBuf,

    /// DNS name in certificate
    #[argh(option)]
    dns_name: String,

    /// number of clients to simulate, default value is 1
    #[argh(option)]
    num_clients: String,
}

#[derive(Debug)]
enum CoapServerWithConnectionInitError {
    ChannelWriteError,
    AddrNotAvailable,
    InvalidCommandLineParameter(String),
    ConnectionError(std::io::Error),
    StreamReadError,
    StreamWriteError,
}

impl fmt::Display for CoapServerWithConnectionInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CoapServerWithConnectionInitError::ChannelWriteError => {
                write!(f, "Failed to write to the channel")
            }
            &CoapServerWithConnectionInitError::AddrNotAvailable => {
                write!(f, "Address is not available")
            }
            CoapServerWithConnectionInitError::InvalidCommandLineParameter(
                e,
            ) => write!(f, "Invalid command line parameter {}", e),
            CoapServerWithConnectionInitError::ConnectionError(e) => {
                write!(f, "Cannot connect to peer: {}", e.to_string())
            }
            &CoapServerWithConnectionInitError::StreamReadError => {
                write!(f, "Cannot read from the stream")
            }
            &CoapServerWithConnectionInitError::StreamWriteError => {
                write!(f, "Cannot write to the stream")
            }
        }
    }
}

impl std::error::Error for CoapServerWithConnectionInitError {}

type ResultCoapServerWithConnectionInit<T> =
    std::result::Result<T, CoapServerWithConnectionInitError>;

#[tokio::main(worker_threads = 64)]
async fn main() -> ResultCoapServerWithConnectionInit<()> {
    env_logger::init();

    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()
        .map_err(|_| CoapServerWithConnectionInitError::AddrNotAvailable)?
        .next()
        .ok_or_else(|| CoapServerWithConnectionInitError::AddrNotAvailable)?;
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;
    let ca_certs = load_certs(&options.ca)?;

    let mut config = ClientConfig::new();
    config
        .set_single_client_cert(certs, keys.remove(0))
        .map_err(|_| {
            CoapServerWithConnectionInitError::InvalidCommandLineParameter(
                "certificate or keys".to_string(),
            )
        })?;

    for cert in &ca_certs {
        config
            .root_store
            .add(cert)
            .expect("Cannot add root certificate to the store");
    }

    let dns_name = &options.dns_name;
    let num_clients =
        u64::from_str_radix(&options.num_clients, 10).unwrap_or(1);
    let opened_connections = Arc::new(AtomicU64::new(0));
    for i in 0..num_clients {
        let config = config.clone();
        let addr = addr.clone();
        let dns_name = dns_name.to_owned();
        let opened_connections = opened_connections.clone();
        tokio::spawn(async move {
            let fut = async {
                let connector = TlsConnector::from(Arc::new(config));
                info!("Connecting to host {}", i);
                let stream = TcpStream::connect(addr).await.map_err(|e| {
                    CoapServerWithConnectionInitError::ConnectionError(e)
                })?;
                let domain =
                DNSNameRef::try_from_ascii_str(&dns_name).map_err(|_| {
                    CoapServerWithConnectionInitError::InvalidCommandLineParameter("dns_name".to_string())
                })?;
                info!("Setting TLS {}", i);
                let stream =
                    connector.connect(domain, stream).await.map_err(|e| {
                        CoapServerWithConnectionInitError::ConnectionError(e)
                    })?;

                let (mut read_half, write_half) = split(stream);
                let opened_cnt = opened_connections
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("Opened connections: {}", opened_cnt + 1);
                handle_incoming_stream(
                    &mut read_half,
                    write_half,
                )
                .await?;
                debug!("Shutting down the stream");
                Ok(()) as ResultCoapServerWithConnectionInit<()>
            };
            if let Err(e) = fut.await {
                warn!(
                    "Error while connecting to the server {}",
                    e.to_string()
                );
            }
        });
    }
    loop {
        sleep(Duration::from_millis(10)).await;
    }
}

async fn send_csm(
    write_tx: mpsc::Sender<Vec<u8>>,
) -> ResultCoapServerWithConnectionInit<()> {
    let mut csm = PacketTcp::new();
    // set CSM message code
    csm.set_code("7.01");
    let mut max_size = LinkedList::new();
    max_size.push_front(1152_u16.to_be_bytes().to_vec());
    csm.set_option(CoapOption::MaxMessageSize, max_size);
    let csm_bytes = csm.to_bytes().unwrap();
    write_tx
        .send(csm_bytes)
        .await
        .map_err(|_| CoapServerWithConnectionInitError::ChannelWriteError)?;
    Ok(())
}

async fn handle_incoming_stream(
    read_half: &mut (impl AsyncRead + Unpin),
    write_half: WriteHalf<TlsStream<TcpStream>>,
) -> ResultCoapServerWithConnectionInit<()> {
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(30);
    tokio::spawn(async move {
        let mut write_half = write_half;
        loop {
            if let Some(data) = write_rx.recv().await {
                if let Err(_) = write_half.write_all(&data).await {
                    let _ = write_half.shutdown().await;
                    return Err(
                        CoapServerWithConnectionInitError::StreamWriteError,
                    );
                };
                write_half.flush().await.map_err(|_| {
                    CoapServerWithConnectionInitError::StreamWriteError
                })?;
            } else {
                let _ = write_half.shutdown().await;
                break;
            }
        }
        Ok(())
    });
    send_csm(write_tx.clone()).await?;
    let mut buf = vec![0; 1024];
    let mut cursor = 0;
    loop {
        if cursor == buf.len() {
            buf.resize(cursor * 2, 0)
        }
        match PacketTcp::check_buf(&buf[..]) {
            Some(packet_bytes_count) if (cursor >= packet_bytes_count) => {
                let packet_bytes: Vec<u8> =
                    buf.drain(..packet_bytes_count).collect();
                process_incoming_packet(packet_bytes, write_tx.clone())
                    .await?;
                cursor -= packet_bytes_count;
                continue;
            }
            _ => {}
        };
        let bytes_read = read_half
            .read(&mut buf[cursor..])
            .await
            .map_err(|_| CoapServerWithConnectionInitError::StreamReadError)?;
        cursor += bytes_read;
        if bytes_read == 0 {
            break;
        }
    }
    Ok(())
}

async fn process_incoming_packet(
    packet_bytes: Vec<u8>,
    write_tx: Sender<Vec<u8>>,
) -> ResultCoapServerWithConnectionInit<()> {
    let parsed_packet = match PacketTcp::from_bytes(packet_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => {
            warn!("Failed to parse the packet {:?}", packet_bytes);
            return Ok(());
        }
    };

    debug!("Incoming packet with type {}", parsed_packet.get_code());
    let payload = parsed_packet.get_payload();
    if payload.len() > 0 {
        debug!(
            "Payload: {}",
            String::from_utf8(payload.to_owned())
                .unwrap_or("Error decoding the payload".to_owned())
        )
    }
    let options = parsed_packet.options();
    if options.len() > 0 {
        debug!("Options:");
        for option in options {
            let option_value = option
                .1
                .iter()
                .map(|opt| {
                    String::from_utf8(opt.to_owned()).unwrap_or_default()
                })
                .collect::<Vec<String>>()
                .join(", ");
            debug!("   {}: {}, raw: {:x?}", option.0, option_value, option.1);
        }
    }
    match parsed_packet.get_message_class() {
        MessageClass::Signaling(SignalType::Ping) => {
            send_pong(write_tx).await
        }
        MessageClass::Signaling(SignalType::CSM) => Ok(()),
        _ => {
            let request = match
                CoapRequest::from_packet(parsed_packet) {
                    Some(r) => r,
                    None => return Ok(())
                };
            let path = request.get_path();
            let observe_flag = request.get_observe_flag();
            let payload = match &path[..] {
                "motion" => {
                    if let Some(flag) = observe_flag {
                        if flag == ObserveOption::Register {
                            register_address_for_observe(
                                write_tx.clone(),
                                request.clone(),
                            );
                        }
                    }
                    generate_motion_stat().as_bytes().to_vec()
                }
                _ => b"OK".to_vec(),
            };

            let mut response = match CoapResponse::from_request(&request,ResponseType::Content) {
                Some(r) => r,
                None => {
                    warn!("Failed to construct response from request object {:?}", request);
                    return Ok(())
                }
            };
            response.set_payload(payload);
            if observe_flag.map_or(false, |el| el == ObserveOption::Register) {
                response.set_observe_value(generate_observe_value());
            }
            let packet = response.to_bytes().unwrap();
            trace!("Replying with packet {:?}", packet);
            write_tx.send(packet).await.map_err(|_| {
                CoapServerWithConnectionInitError::StreamWriteError
            })

        }
    }
}

async fn send_pong(write_tx: Sender<Vec<u8>>) -> ResultCoapServerWithConnectionInit<()> {
    trace!("Sending Pong");
    let pong = CoapSignal::new(SignalType::Pong);
    write_tx
        .send(pong.to_bytes().unwrap())
        .await
        .map_err(|_| CoapServerWithConnectionInitError::StreamWriteError)
}

fn load_certs(
    path: &Path,
) -> ResultCoapServerWithConnectionInit<Vec<Certificate>> {
    let file = File::open(path).map_err(|_| {
        CoapServerWithConnectionInitError::InvalidCommandLineParameter(
            "certificate".to_string(),
        )
    })?;
    certs(&mut BufReader::new(file)).map_err(|_| {
        CoapServerWithConnectionInitError::InvalidCommandLineParameter(
            "certificate".to_string(),
        )
    })
}

fn load_keys(
    path: &Path,
) -> ResultCoapServerWithConnectionInit<Vec<PrivateKey>> {
    let file = File::open(path).map_err(|_| {
        CoapServerWithConnectionInitError::InvalidCommandLineParameter(
            "key".to_string(),
        )
    })?;
    pkcs8_private_keys(&mut BufReader::new(file)).map_err(|_| {
        CoapServerWithConnectionInitError::InvalidCommandLineParameter(
            "key".to_string(),
        )
    })
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
    write_tx: Sender<Vec<u8>>,
    request: CoapRequest<PacketTcp>,
) {
    let start_time = chrono::Utc::now();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(10000)).await;
            let mut response = match CoapResponse::from_request(&request,ResponseType::Content) {
                Some(r) => r,
                None => {
                    warn!("Failed to construct response from request object {:?}", request);
                    continue;
                }
            };
            response.set_observe_value(generate_observe_value());
            response
                .set_payload(generate_motion_stat().as_bytes().into());
            let mut etag_option: LinkedList<Vec<u8>> = LinkedList::new();
            etag_option.push_front(
                chrono::Utc::now().timestamp().to_be_bytes().to_vec(),
            );
            response
                .set_option(coap_lite::CoapOption::ETag, etag_option);
            trace!("Sending the observe message {:?}", response);
            let packet = response.to_bytes().unwrap();
            if let Err(_) = write_tx.send(packet).await {
                break;
            }
            if chrono::Utc::now().timestamp() - start_time.timestamp() > 600000
            {
                debug!("Timeout reached, stopping notifications");
                break;
            }
        }
    });
}

fn generate_observe_value() -> Vec<u8> {
    let timestamp_bytes =
        chrono::Local::now().timestamp_millis().to_be_bytes();
    timestamp_bytes[timestamp_bytes.len() - 3..].to_vec()
}
