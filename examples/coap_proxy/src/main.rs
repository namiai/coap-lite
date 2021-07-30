mod banlist_checker;
mod certificate;
mod client_cert_verifier;
mod client_connection;
mod connected_clients_tracker;
mod error;
mod message_sink;
mod message_source;
mod to_device_message_fetcher;

use argh::FromArgs;
use client_connection::RequestResponseMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::*;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::Session;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use banlist_checker::RedisBanListChecker;
use client_cert_verifier::AllowAuthenticatedClientsWithNotBannedCertificates;

use crate::certificate::extract_cn_from_presented_certificates;
use crate::client_connection::ClientConnection;
use crate::connected_clients_tracker::ConnectedClientsTracker;
use crate::error::CoapProxyError;
use crate::message_sink::RedisMessageSink;
use crate::to_device_message_fetcher::ToDeviceMessageFetcher;

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

type ResultCoapProxy<T> = std::result::Result<T, CoapProxyError>;
pub struct ConnectedClientEntry {
    write_tx: Sender<Vec<u8>>,
    request_response_map: Arc<Mutex<RequestResponseMap>>,
}

type ConnectedClientsMap = Arc<RwLock<HashMap<String, ConnectedClientEntry>>>;

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

    let config =
        create_tls_config(&options).expect("Failed to create TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|_| CoapProxyError::BindError)?;

    let sink = Arc::new(
        RedisMessageSink::new(&options.sink_redis_url, "from_device")
            .expect("Failed to create redis message sink"),
    );

    // Keeps the mapping between the client common name and the connection handles
    let connected_clients_map: ConnectedClientsMap =
        Arc::new(RwLock::new(HashMap::new()));
    // helper var to keep the number of connected clients
    let connected_clients_tracker = Arc::new(ConnectedClientsTracker::new());

    let to_device_message_fetcher =
        ToDeviceMessageFetcher::new(&options.source_redis_url);
    to_device_message_fetcher
        .start_fetching_messages(connected_clients_map.clone());
    info!("Proxy started");
    // block the second connection using the same CN
    loop {
        let connected_clients_map = connected_clients_map.clone();
        let connected_clients_tracker = connected_clients_tracker.clone();
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| CoapProxyError::AcceptingConnectionError(e))?;
        connected_clients_tracker.record_client_connected();
        let acceptor = acceptor.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                let certificates =
                    stream.get_ref().1.get_peer_certificates().unwrap();
                let cn = match extract_cn_from_presented_certificates(
                    &certificates,
                ) {
                    Ok(cn) => cn,
                    Err(e) => {
                        warn!("Error while extracting CN: {}", e);
                        return;
                    }
                };
                let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(30);
                let mut client_connection =
                    ClientConnection::new(write_tx.clone(), &cn, &sink);
                let connected_client_entry = ConnectedClientEntry {
                    write_tx: write_tx.clone(),
                    request_response_map: client_connection
                        .request_response_map
                        .clone(),
                };
                connected_clients_map
                    .write()
                    .await
                    .insert(cn.to_owned(), connected_client_entry);
                match client_connection.process_stream(stream, write_rx).await
                {
                    Ok(_) => {
                        debug!("Shutdowning stream");
                    }
                    Err(e) => warn!("Error during the stream handling: {}", e),
                }
                connected_clients_tracker.record_client_disconnected();
                connected_clients_map.write().await.remove(&cn);
            }
        });
    }
}

/// Loads keys / certificates and creates TLS config
fn create_tls_config(options: &Options) -> ResultCoapProxy<ServerConfig> {
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
    Ok(config)
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

pub fn generate_random_token() -> [u8; 4] {
    rand::random::<[u8; 4]>()
}
