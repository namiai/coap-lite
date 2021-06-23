use argh::FromArgs;
use coap_lite::{
    CoapOption, CoapRequest, CoapResponse, MessageClass, Packet, PacketTcp,
    RequestType, SignalType,
};
use std::collections::LinkedList;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{
    Certificate, NoClientAuth, PrivateKey, ServerConfig,
};
use tokio_rustls::TlsAcceptor;

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
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = async move {
            let mut stream = acceptor.accept(stream).await?;
            handle_incoming_stream(&mut stream).await?;
            stream.shutdown().await?;
            Ok(()) as io::Result<()>
        };
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

async fn send_csm(writer: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
    let mut csm = PacketTcp::new();
    // set CSM message code
    csm.set_code("7.01");
    let mut max_size = LinkedList::new();
    max_size.push_front(1152_u16.to_be_bytes().to_vec());
    csm.set_option(CoapOption::MaxMessageSize, max_size);
    let csm_bytes = csm.to_bytes().unwrap();
    writer.write(&csm_bytes).await?;

    Ok(())
}

async fn handle_incoming_stream(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> io::Result<()> {
    send_csm(stream).await?;
    send_motion_observe(stream).await?;
    loop {
        let mut buf = Vec::new();
        stream.read_buf(&mut buf).await?;
        if buf.len() == 0 {
            continue;
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
                            String::from_utf8(opt.to_owned())
                                .unwrap_or_default()
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
                MessageClass::Signaling(SignalType::Ping) => {
                    send_pong(stream, &parsed_packet).await?;
                }
                _ => continue,
            }
        }
    }
}

async fn send_pong(
    stream: &mut (impl AsyncWrite + Unpin),
    packet: &PacketTcp,
) -> io::Result<()> {
    println!("Sending Pong");
    let mut reply = CoapResponse::new(packet).unwrap();
    reply
        .message
        .set_code_from_message_class(MessageClass::Signaling(
            SignalType::Pong,
        ));
    stream
        .write_all(&reply.message.to_bytes().unwrap()[..])
        .await?;
    Ok(())
}

async fn send_motion_observe(
    stream: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut request: CoapRequest<String, PacketTcp> = CoapRequest::new();
    request.set_method(RequestType::Get);
    request.set_path("/motion");
    request.set_observe_flag(coap_lite::ObserveOption::Register);
    stream
        .write_all(&request.message.to_bytes().unwrap()[..])
        .await?;
    Ok(())
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?)).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid cert")
    })
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?)).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid key")
    })
}
