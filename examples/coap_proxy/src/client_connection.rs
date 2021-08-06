use coap_lite::{
    CoapMessageExt, CoapOption, CoapRequest, CoapSignal, MessageClass, Packet,
    PacketTcp, RequestType, SignalType,
};
use std::{
    collections::{HashMap, LinkedList},
    sync::Arc,
};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
    sync::Mutex,
};
use tokio_rustls::server::TlsStream;

use crate::{
    generate_random_token,
    message_sink::{MessageSink, SinkMesssage},
    CoapProxyError, ResultCoapProxy,
};

/// Helper structure to get the path the request was made to on receiving the response
/// Easier to explain on example:
/// 1. Proxy receives the message to send to device to the path "/status"
/// 2. Proxy assigns random token to the request and sends it to the device
/// 3. Device replies and includes token in the response but doesn't include the path in the headers
/// 4. Proxy fetches the path based on the provided token
pub type RequestResponseMap = HashMap<Vec<u8>, String>;

#[allow(dead_code)]
pub struct ClientConnection<'a, S: MessageSink> {
    pub request_response_map: Arc<Mutex<RequestResponseMap>>,
    write_tx: Sender<Vec<u8>>,
    shutdown_tx: Sender<()>,
    cn: &'a str,
    sink: &'a Arc<S>,
}

impl<'a, S: MessageSink> ClientConnection<'a, S> {
    pub fn new(
        write_tx: Sender<Vec<u8>>,
        shutdown_tx: Sender<()>,
        cn: &'a str,
        sink: &'a Arc<S>,
    ) -> ClientConnection<'a, S> {
        let request_response_map: Arc<Mutex<RequestResponseMap>> =
            Arc::new(Mutex::new(HashMap::new()));
        ClientConnection {
            write_tx,
            shutdown_tx,
            request_response_map,
            cn,
            sink,
        }
    }
    pub async fn process_stream(
        &mut self,
        stream: TlsStream<TcpStream>,
        write_rx: Receiver<Vec<u8>>,
        shutdown_rx: Receiver<()>,
    ) -> ResultCoapProxy<()> {
        let (mut read_half, write_half) = split(stream);
        let mut write_rx = write_rx;
        let mut shutdown_rx = shutdown_rx;
        let cn = self.cn.to_string();
        tokio::spawn(async move {
            let mut write_half = write_half;
            loop {
                // There are 2 channels we look at:
                // Shutdown -- doesn't matter what message come in, we just exit the loop and shutdown the stream
                // Data to write -- contains vec of u8 values to be written to the channel
                //
                // Select should be biased because we prioritize control messages over data
                //
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        info!("Received shutdown signal for the client with CN {}", cn);
                        let _ = write_half.shutdown().await;
                        break;
                    },
                    dt = write_rx.recv() => {
                        if let Some(data) = dt {
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
                }
            }
            Ok(())
        });
        // hardcoded for now, CSM message to indicate the capabilities of the server (e.g max message size)
        self.send_csm().await?;
        // used during the development only:
        // send the observe message to ask the device to start reporting motion events and statistics
        self.send_motion_observe().await?;

        // Actual stream reading code
        //
        // We start with a small buffer and most likely it will be enough for our case
        let mut buf = vec![0; 1024];
        // Cursor keeps track on the position of the last filled byte in the buffer
        let mut cursor = 0;
        loop {
            // self-explanatory -- in case we reached the buffer limit -> increase it and fill with 0's
            // That could be optimized with "bytes" crate to avoid filling the new memory with 0's,
            // but it's probably too early to bother about such things
            if cursor == buf.len() {
                buf.resize(cursor * 2, 0)
            }
            // trying to parse the header of the packet obtain the size we need to read from buffer
            match PacketTcp::check_buf(&buf[..]) {
                // alright, packet seems to be incoming, next thing to check if we received it in full or not yet
                Some(packet_bytes_count) if (cursor >= packet_bytes_count) => {
                    // if yes, drain packet bytes from the buffer
                    let packet_bytes: Vec<u8> =
                        buf.drain(..packet_bytes_count).collect();
                    // adjust the cursors
                    cursor -= packet_bytes_count;
                    // and process incoming packet
                    self.process_incoming_packet(packet_bytes).await?;
                    // we need to go to the beginning of the loop here because
                    // buffer may contain more messages that have been received but not yet processed
                    // need to deal with them first before reading from stream again
                    continue;
                }
                _ => {}
            };
            // reading from stream into the buffer, asynchronously
            // Error may happen if say the stream is closed already
            // nothing else we can do, need to exist the function
            let bytes_read = read_half
                .read(&mut buf[cursor..])
                .await
                .map_err(|_| CoapProxyError::StreamReadError)?;
            // advance the cursor
            cursor += bytes_read;
            // and if nothing has been read -> stream is closed -> exit the function
            if bytes_read == 0 {
                debug!("Shutting down the stream");
                break;
            }
        }
        Ok(())
    }
}

impl<'a, S: MessageSink> ClientConnection<'a, S> {
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
        let path = "/sensing";
        request.set_token(token.into());
        request.set_path(path);
        request.set_observe_flag(coap_lite::ObserveOption::Register);
        let bytes = request.to_bytes().expect(&format!(
            "Cannot encode CoAP message as bytes {:?}",
            request
        ));
        self.write_tx
            .send(bytes)
            .await
            .map_err(|_| CoapProxyError::StreamWriteError)?;
        self.request_response_map
            .lock()
            .await
            .insert(token.into(), path.to_owned());
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
                            return Ok(());
                        }
                        let mut request_response_map =
                            self.request_response_map.lock().await;
                        let path = match request_response_map.get(token) {
                            Some(p) => {
                                trace!("Found the request matching the token {:?}, path is {}", token, p);
                                p.clone()
                            }
                            None => {
                                warn!("Cannot find the corresponding request for token {:?}", token);
                                return Ok(());
                            }
                        };

                        match parsed_packet.get_observe() {
                            Some(_) => {}
                            None => {
                                request_response_map.remove(token);
                            }
                        };
                        path
                    }
                    _ => "".to_owned(),
                };

                if let Err(e) =
                    self.sink.invoke(&SinkMesssage::from_packet_tcp(
                        self.cn,
                        &path,
                        parsed_packet,
                    ))
                {
                    warn!("Failed to sink the incoming message, error: {}", e)
                }
                Ok(())
            }
        }
    }
}
