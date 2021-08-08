use crate::client_connection::RequestResponseMap;
use hex_fmt::HexFmt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::Sender, Mutex};

#[derive(Debug)]
pub struct ConnectedClientEntry {
    pub write_tx: Sender<Vec<u8>>,
    pub shutdown_tx: Sender<()>,
    pub request_response_map: Arc<Mutex<RequestResponseMap>>,
    pub session_id: String,
}

pub type ConnectedClientsMap = HashMap<String, ConnectedClientEntry>;

/// Keeps the association between CN and the stream connection handles
///
pub struct ConnectedClientsTracker {
    pub connected_clients_map: ConnectedClientsMap,
}

impl ConnectedClientsTracker {
    pub fn new() -> ConnectedClientsTracker {
        // Keeps the mapping between the client common name and the connection handles
        let connected_clients_map: ConnectedClientsMap = HashMap::new();

        ConnectedClientsTracker {
            connected_clients_map,
        }
    }

    pub async fn record_client_connected(
        &mut self,
        cn: &str,
        connected_client_entry: ConnectedClientEntry,
    ) {
        let existing_session_id = connected_client_entry.session_id.clone();
        let existing_record = self
            .connected_clients_map
            .insert(cn.to_owned(), connected_client_entry);
        if let Some(v) = existing_record {
            info!("New client with the same CN {} is connected (existing session id {:10}, new session id {:10}), disconnecting the existing session", cn, HexFmt(existing_session_id), HexFmt(v.session_id));
            let _ = v.shutdown_tx.send(()).await;
        }
        debug!(
            "Client connected, connected count: {}",
            self.connected_clients_map.keys().len()
        );
    }

    pub async fn record_client_disconnected(
        &mut self,
        cn: &str,
        session_id: &str,
    ) {
        if let Some(entry) = self.connected_clients_map.get(cn) {
            if entry.session_id == session_id {
                self.connected_clients_map.remove(cn);
            }
        }
        debug!(
            "Client disconnected, connected count: {}",
            self.connected_clients_map.keys().len()
        );
    }
}
