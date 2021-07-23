use coap_lite::{
    CoapMessageExt, CoapOption, CoapRequest, CoapSignal, MessageClass, Packet,
    PacketTcp, RequestType, SignalType,
};
use std::{collections::{HashMap, LinkedList}, sync::Arc};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
};
use tokio_rustls::server::TlsStream;

use crate::{CoapProxyError, ResultCoapProxy, generate_random_token, message_sink::MessageSink};

pub struct ClientConnection<'a, S: MessageSink<PacketTcp>> {
    request_response_map: HashMap<Vec<u8>, String>,
    write_tx: Sender<Vec<u8>>,
    cn: &'a str,
    sink: &'a Arc<S>,
}

impl<'a, S: MessageSink<PacketTcp>> ClientConnection<'a, S> {
    pub fn new(
        write_tx: Sender<Vec<u8>>,
        cn: &'a str,
        sink: &'a Arc<S>,
    ) -> ClientConnection<'a, S> {
        let request_response_map: HashMap<Vec<u8>, String> = HashMap::new();
        ClientConnection {
            write_tx,
            request_response_map,
            cn,
            sink,
        }
    }
    pub async fn process_stream(
        &mut self,
        stream: TlsStream<TcpStream>,
        write_rx: Receiver<Vec<u8>>,
    ) -> ResultCoapProxy<()> {
        let (mut read_half, write_half) = split(stream);
        let mut write_rx = write_rx;
        tokio::spawn(async move {
            let mut write_half = write_half;
            loop {
                if let Some(data) = write_rx.recv().await {
                    debug!("Writing the data to the stream {:?}", data);
                    if let Err(_) = write_half.write_all(&data).await {
                        let _ = write_half.shutdown().await;
                        return Err(CoapProxyError::StreamWriteError);
                    };
                    write_half
                        .flush()
                        .await
                        .map_err(|_| CoapProxyError::StreamWriteError)?;
                } else {
                    let _ = write_half.shutdown().await;
                    break;
                }
            }
            Ok(())
        });
        self.send_csm().await?;
        self.send_motion_observe().await?;
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
                    self.process_incoming_packet(packet_bytes).await?;
                    cursor -= packet_bytes_count;
                    continue;
                }
                _ => {}
            };
            let bytes_read = read_half
                .read(&mut buf[cursor..])
                .await
                .map_err(|_| CoapProxyError::StreamReadError)?;
            cursor += bytes_read;
            if bytes_read == 0 {
                debug!("Shutting down the stream");
                break;
            }
        }
        Ok(())
    }
}

impl<'a, S: MessageSink<PacketTcp>> ClientConnection<'a, S> {
    async fn send_pong(&self) -> ResultCoapProxy<()> {
        trace!("Sending Pong");
        let pong = CoapSignal::new(SignalType::Pong);
        self.write_tx
            .send(pong.to_bytes().unwrap())
            .await
            .map_err(|_| CoapProxyError::StreamWriteError)
    }

    async fn send_motion_observe(&mut self) -> ResultCoapProxy<()> {
        let mut request: CoapRequest<PacketTcp> =
            CoapRequest::new(RequestType::Get);
        let token = generate_random_token();
        let path = "/motion";
        request.set_token(token.into());
        request.set_path("/motion");
        request.set_observe_flag(coap_lite::ObserveOption::Register);
        let bytes = request.to_bytes().expect(&format!(
            "Cannot encode CoAP message as bytes {:?}",
            request
        ));
        self.write_tx
            .send(bytes)
            .await
            .map_err(|_| CoapProxyError::StreamWriteError)?;
        self.request_response_map.insert(token.into(), path.to_owned());
        Ok(())
    }

    async fn send_csm(&self) -> ResultCoapProxy<()> {
        let mut csm = PacketTcp::new();
        // set CSM message code
        csm.set_code("7.01");
        let mut max_size = LinkedList::new();
        max_size.push_front(1152_u16.to_be_bytes().to_vec());
        csm.set_option(CoapOption::MaxMessageSize, max_size);
        let csm_bytes = csm.to_bytes().unwrap();
        self.write_tx
            .send(csm_bytes)
            .await
            .map_err(|_| CoapProxyError::ChannelWriteError)?;

        Ok(())
    }

    async fn process_incoming_packet(
        &mut self,
        packet_bytes: Vec<u8>,
    ) -> ResultCoapProxy<()> {
        let parsed_packet =
            match PacketTcp::from_bytes(packet_bytes.as_slice()) {
                Ok(p) => p,
                Err(_) => {
                    warn!("Failed to parse the packet {:?}", packet_bytes);
                    return Ok(());
                }
            };

        debug!("Incoming packet with type {}", parsed_packet.get_code());
        let token = parsed_packet.get_token();
        if token.len() > 0 {
            trace!("Token: {:?}", token);
        }
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
                trace!(
                    "   {}: {}, raw: {:x?}",
                    option.0,
                    option_value,
                    option.1
                );
            }
        }
        match parsed_packet.get_message_class() {
            MessageClass::Signaling(SignalType::Ping) => {
                self.send_pong().await
            }
            MessageClass::Signaling(SignalType::CSM) => Ok(()),
            _ => {
                let path: String = match parsed_packet.get_message_class() {
                    MessageClass::Request(_) => parsed_packet.get_path(),
                    MessageClass::Response(_) => {
                        let token = parsed_packet.get_token();
                        if token.len() == 0 {
                            warn!("No token in response {:?}", parsed_packet);
                            return Ok(())
                        }
                        let path = match self.request_response_map.get(token) {
                            Some(p) => p.clone(),
                            None => {
                                warn!("Cannot find the corresponding request for token {:?}", token);
                                return Ok(())
                            }
                        };

                        match parsed_packet.get_observe() {
                            Some(_) => {},
                            None => {
                                self.request_response_map.remove(token);
                            }
                        };
                        path
                    },
                    _ => "".to_owned()
                };
                if let Err(e) = self.sink.process_incoming_message(
                    parsed_packet,
                    self.cn,
                    &path,
                ) {
                    warn!("Failed to sink the incoming message, error: {}", e)
                }
                Ok(())
            }
        }
    }
}
