mod banlist_checker;
mod client_cert_verifier;
mod message_sink;
mod message_source;
mod certificate;

use argh::FromArgs;
use coap_lite::{
    CoapOption, CoapRequest, CoapResponse, MessageClass, Packet, PacketTcp,
    RequestType, SignalType,
};
use tokio_rustls::rustls::Session;
use x509_parser::nom::bytes;
use core::fmt;
use std::collections::HashMap;
use std::collections::LinkedList;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::*;
use tokio::sync::mpsc::Sender;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use banlist_checker::RedisBanListChecker;
use client_cert_verifier::AllowAuthenticatedClientsWithNotBannedCertificates;

use crate::message_sink::{MessageSink, RedisMessageSink};
use crate::message_source::MessageSource;
use certificate::extract_cn_from_presented_certificates;
use crate::message_source::RedisMessageSource;

extern crate redis;

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

    /// banlist redis url
    #[argh(option)]
    banlist_redis_url: String,

    /// sink redis url
    #[argh(option)]
    sink_redis_url: String,

    /// sink redis url
    #[argh(option)]
    source_redis_url: String,
}

#[derive(Debug)]
enum CoapProxyError {
    ChannelWriteError,
    AddrNotAvailable,
    InvalidCommandLineParameter(String),
    BindError,
    AcceptingConnectionError(io::Error),
    StreamReadError,
    StreamWriteError,
}

impl fmt::Display for CoapProxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CoapProxyError::ChannelWriteError => {
                write!(f, "Failed to write to the channel")
            }
            &CoapProxyError::AddrNotAvailable => {
                write!(f, "Address is not available")
            }
            CoapProxyError::InvalidCommandLineParameter(e) => {
                write!(f, "Invalid command line parameter {}", e)
            }
            &CoapProxyError::BindError => write!(f, "Cannot bind the port"),
            CoapProxyError::AcceptingConnectionError(e) => {
                write!(f, "Cannot accept incoming connection: {}",e.to_string())
            }
            &CoapProxyError::StreamReadError => {
                write!(f, "Cannot read from the stream")
            }
            &CoapProxyError::StreamWriteError => {
                write!(f, "Cannot write to the stream")
            }
        }
    }
}

type ResultCoapProxy<T> = std::result::Result<T, CoapProxyError>;

#[tokio::main]
async fn main() -> ResultCoapProxy<()> {
    env_logger::init();

    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()
        .map_err(|_| CoapProxyError::AddrNotAvailable)?
        .next()
        .ok_or_else(|| CoapProxyError::AddrNotAvailable)?;
    let certs = load_certs(&options.cert)?;
    let ca_certs = load_certs(&options.ca)?;
    let mut keys = load_keys(&options.key)?;

    let mut certs_store = RootCertStore::empty();
    for cert in &certs {
        certs_store
            .add(cert)
            .expect("Cannot add certificate to the certs store");
    }
    for cert in &ca_certs {
        certs_store
            .add(cert)
            .expect("Cannot add certificate to the certs store");
    }
    // let banlist_checker = StaticBanListChecker::new(vec!["device1", "device2"]);
    let banlist_checker = RedisBanListChecker::new(&options.banlist_redis_url)
        .expect("Failed to create redis ban list checker");
    let mut config = ServerConfig::new(
        AllowAuthenticatedClientsWithNotBannedCertificates::new(
            certs_store,
            banlist_checker,
        ),
    );
    config.set_single_cert(certs, keys.remove(0)).map_err(|_| {
        CoapProxyError::InvalidCommandLineParameter(
            "certificate or keys".to_string(),
        )
    })?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|_| CoapProxyError::BindError)?;

    let sink = Arc::new(
        RedisMessageSink::new(&options.sink_redis_url, "from_device")
            .expect("Failed to create redis message sink"),
        // DevNullMessageSink::new()
    );
    let source = RedisMessageSource::new(&options.source_redis_url, "to_device").expect("Failed to create redis message source");

    let connected_clients_map:Arc<RwLock<HashMap<String, Sender<Vec<u8>>>>> = Arc::new(RwLock::new(HashMap::new()));
    let connected_clients_cnt = Arc::new(AtomicU64::new(0));

    let local_connected_clients_map = connected_clients_map.clone();
    tokio::spawn(async move {
        loop {
            let local_connected_clients_map = local_connected_clients_map.clone();
            match source.fetch_new_message() {
                Ok((packet, cn)) =>{
                    let packet:PacketTcp = packet;
                    let packet = match packet.to_bytes() {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            warn!("Failed to convert the packet to bytes: {}", e.to_string());
                            continue;
                        }
                    };
                    let connected_clients_map = local_connected_clients_map.read().await;
                    let client = match connected_clients_map.get(&cn) {
                        Some(client) => client,
                        None => {
                            warn!("Client with CN {} is not connected", cn);
                            continue;
                        }
                    };
                    if let Err(e) = client.send(packet).await {
                        warn!("Failed to send the message to the device {}: {}", cn, e.to_string());
                    }

                },
                Err(e) => {
                    warn!("Failed to get message from source: {}", e.to_string());
                    continue;
                }
            }


        }
    });
    info!("Proxy started");
    loop {
        let mut connected_clients_map = connected_clients_map.clone();
        let connected_clients_cnt = connected_clients_cnt.clone();
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| CoapProxyError::AcceptingConnectionError(e))?;
        let clients_cnt = connected_clients_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        info!("Accepted connection, total clients {}", clients_cnt + 1);
        let acceptor = acceptor.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                let certificates = stream.get_ref().1.get_peer_certificates().unwrap();
                let cn = match extract_cn_from_presented_certificates(&certificates) {
                    Ok(cn) => cn,
                    Err(e) => {
                        warn!("Error while extracting CN: {}", e);
                        return;
                    }
                };
                let (mut read_half, write_half) = split(stream);
                match handle_incoming_stream(&mut read_half, write_half, sink, &mut connected_clients_map, cn.to_owned())
                    .await
                {
                    Ok(_) => {
                        debug!("Shutdowning stream");
                    },
                    Err(e) => warn!("Error during the stream handling: {}", e),
                }
                let clients_cnt = connected_clients_cnt.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                info!("Client disconnected, total clients {}", clients_cnt - 1);
                connected_clients_map.write().await.remove(&cn);
            }
        });
    }
}

async fn send_csm(write_tx: Sender<Vec<u8>>) -> ResultCoapProxy<()> {
    let mut csm = PacketTcp::new();
    // set CSM message code
    csm.set_code("7.01");
    let mut max_size = LinkedList::new();
    max_size.push_front(1152_u16.to_be_bytes().to_vec());
    csm.set_option(CoapOption::MaxMessageSize, max_size);
    let csm_bytes = csm.to_bytes().unwrap();
    write_tx.send(csm_bytes).await.map_err(|_| CoapProxyError::ChannelWriteError)?;

    Ok(())
}

async fn handle_incoming_stream<S: MessageSink<PacketTcp>>(
    read_half: &mut (impl AsyncRead + Unpin),
    write_half: WriteHalf<TlsStream<TcpStream>>,
    sink: Arc<S>,
    connected_clients_map: &mut Arc<RwLock<HashMap<String, Sender<Vec<u8>>>>>,
    cn: String
) -> ResultCoapProxy<()> {
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(30);
    let mut connected_clients_map = connected_clients_map.write().await;
    connected_clients_map.insert(cn, write_tx.clone());
    tokio::spawn(async move {
        let mut write_half = write_half;
        loop {
            if let Some(data) = write_rx.recv().await {
                if let Err(_) = write_half.write_all(&data).await {
                    let _ = write_half.shutdown().await;
                    return Err(
                        CoapProxyError::StreamWriteError,
                    );
                };
                write_half.flush().await.map_err(|_| {
                    CoapProxyError::StreamWriteError
                })?;
            } else {
                let _ = write_half.shutdown().await;
                break;
            }
        }
        Ok(())
    });

    send_csm(write_tx.clone()).await?;
    send_motion_observe(write_tx.clone()).await?;
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
                process_incoming_packet(packet_bytes, write_tx.clone(), &sink).await?;
                cursor -= packet_bytes_count;
                continue;
            }
            _ => {}
        };
        let bytes_read = read_half.read(&mut buf[cursor..]).await.map_err(|_| CoapProxyError::StreamReadError)?;
        cursor += bytes_read;
        if bytes_read == 0 {
            debug!("Shutting down the stream");
            break;
        }
    }
    Ok(())
}

async fn process_incoming_packet<S: MessageSink<PacketTcp>>(
    packet_bytes: Vec<u8>,
    write_tx: Sender<Vec<u8>>,
    sink: &Arc<S>,
) -> ResultCoapProxy<()> {
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
        trace!(
            "Payload: {}",
            String::from_utf8(payload.to_owned())
                .unwrap_or("Error decoding the payload".to_owned())
        )
    }
    let options = parsed_packet.options();
    if options.len() > 0 {
        trace!("Options:");
        for option in options {
            let option_value = option
                .1
                .iter()
                .map(|opt| {
                    String::from_utf8(opt.to_owned()).unwrap_or_default()
                })
                .collect::<Vec<String>>()
                .join(", ");
            trace!("   {}: {}, raw: {:x?}", option.0, option_value, option.1);
        }
    }
    match parsed_packet.get_message_class() {
        MessageClass::Signaling(SignalType::Ping) => {
            send_pong(write_tx.clone(), &parsed_packet).await
        }
        MessageClass::Signaling(SignalType::CSM) => Ok(()),
        _ => {
            if let Err(e) = sink.process_incoming_message(parsed_packet) {
                warn!("Failed to sink the incoming message, error: {}", e)
            }
            Ok(())
        }
    }
}

async fn send_pong(
    write_tx: Sender<Vec<u8>>,
    packet: &PacketTcp,
) -> ResultCoapProxy<()> {
    trace!("Sending Pong");
    let mut reply = CoapResponse::new(packet).unwrap();
    reply
        .message
        .set_code_from_message_class(MessageClass::Signaling(
            SignalType::Pong,
        ));
    write_tx
        .send(reply.message.to_bytes().unwrap())
        .await.map_err(|_| CoapProxyError::StreamWriteError)
}

async fn send_motion_observe(write_tx: Sender<Vec<u8>>) -> ResultCoapProxy<()> {
    let mut request: CoapRequest<String, PacketTcp> = CoapRequest::new();
    request.set_method(RequestType::Get);
    request.set_path("/motion");
    request.set_observe_flag(coap_lite::ObserveOption::Register);
    let bytes = request.message.to_bytes().expect(&format!(
        "Cannot encode CoAP message as bytes {:?}",
        request.message
    ));
    write_tx.send(bytes).await.map_err(|_| CoapProxyError::StreamWriteError)
}

fn load_certs(path: &Path) -> ResultCoapProxy<Vec<Certificate>> {
    let file = File::open(path).map_err(|_| {
        CoapProxyError::InvalidCommandLineParameter("certificate".to_string())
    })?;
    certs(&mut BufReader::new(file)).map_err(|_| {
        CoapProxyError::InvalidCommandLineParameter("certificate".to_string())
    })
}

fn load_keys(path: &Path) -> ResultCoapProxy<Vec<PrivateKey>> {
    let file = File::open(path).map_err(|_| {
        CoapProxyError::InvalidCommandLineParameter("key".to_string())
    })?;
    pkcs8_private_keys(&mut BufReader::new(file)).map_err(|_| {
        CoapProxyError::InvalidCommandLineParameter("key".to_string())
    })
}
