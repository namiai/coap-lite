use std::sync::Arc;

use base64::decode;
use coap_lite::{MessageClass, Packet, PacketTcp};

use crate::{
    generate_random_token,
    message_source::{MessageSource, MessageToDevice, RedisMessageSource},
    ConnectedClientsMap,
};
use tokio;

pub struct ToDeviceMessageFetcher<T>
where
    T: MessageSource + Send + Sync + 'static,
{
    message_source: Arc<T>,
}

impl ToDeviceMessageFetcher<RedisMessageSource> {
    pub fn new(redis_url: &str) -> ToDeviceMessageFetcher<RedisMessageSource> {
        ToDeviceMessageFetcher {
            message_source: Arc::new(
                RedisMessageSource::new(redis_url, "to_device")
                    .expect("Failed to create redis message source"),
            ),
        }
    }
}

impl<T: MessageSource + Send + Sync + 'static> ToDeviceMessageFetcher<T> {
    /// Message source constantly polls the source from redis
    /// As soon as something is found it will push the message to the channel of the associated client
    ///
    pub fn start_fetching_messages(
        &self,
        connected_clients_map: ConnectedClientsMap,
    ) {
        debug!("Starting message source");
        let source = self.message_source.clone();
        tokio::spawn(async move {
            loop {
                let source = source.clone();
                // fetch_new_message is not async so making sure that the task
                // doesn't block other tokio tsks
                match tokio::task::spawn_blocking(move || {
                    source.fetch_new_message()
                })
                .await
                {
                    Ok(Ok(msg_to_send)) => {
                        let cn = &msg_to_send.cn;
                        let packet =
                            match create_packet_from_message(&msg_to_send) {
                                Some(p) => p,
                                None => continue,
                            };

                        let packet_bytes = match packet.to_bytes() {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                warn!(
                                "Failed to convert the packet to bytes: {}",
                                e.to_string()
                            );
                                continue;
                            }
                        };
                        let connected_clients_map =
                            connected_clients_map.read().await;
                        let connected_client_entry =
                            match connected_clients_map.get(cn) {
                                Some(write_tx) => write_tx,
                                None => {
                                    warn!(
                                        "Client with CN {} is not connected",
                                        cn
                                    );
                                    continue;
                                }
                            };
                        let token = packet.get_token();
                        if !token.is_empty() {
                            connected_client_entry
                                .request_response_map
                                .lock()
                                .await
                                .insert(
                                    token.clone(),
                                    msg_to_send.path.clone(),
                                );
                        }
                        if let Err(e) = connected_client_entry
                            .write_tx
                            .send(packet_bytes)
                            .await
                        {
                            warn!(
                            "Failed to send the message to the device {}: {}",
                            cn,
                            e.to_string()
                        );
                            if !token.is_empty() {
                                connected_client_entry
                                    .request_response_map
                                    .lock()
                                    .await
                                    .remove(&token.to_vec());
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "Failed to get message from source: {}",
                            e.to_string()
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Failed run blocking closure: {}",
                            e.to_string()
                        );
                        continue;
                    }
                }
            }
        });
    }
}
fn create_packet_from_message(
    msg_to_send: &MessageToDevice,
) -> Option<PacketTcp> {
    let mut packet: PacketTcp = PacketTcp::new();
    packet.set_code(&msg_to_send.code);
    let payload = match decode(msg_to_send.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to decode base64 message: {}", e.to_string());
            return None;
        }
    };

    // Token is set only when we need to forward the request
    // Response will go as is.
    // Token will be later used to fetch the endpoint request was sent to
    let token = match packet.get_message_class() {
        MessageClass::Request(_) => {
            let token = generate_random_token().to_vec();
            trace!(
                "Message to send is of type request, setting token {:?}",
                token
            );
            token
        }
        _ => vec![],
    };
    packet.set_token(token.clone());
    packet.set_path(&msg_to_send.path);
    packet.set_payload(payload);
    Some(packet)
}
