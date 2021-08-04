use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc},
};

use tokio::sync::{mpsc::Sender, Mutex};

use crate::client_connection::RequestResponseMap;

#[derive(Debug)]
pub struct ConnectedClientEntry {
    pub write_tx: Sender<Vec<u8>>,
    pub shutdown_tx: Sender<()>,
    pub request_response_map: Arc<Mutex<RequestResponseMap>>,
    pub session_id: [u8; 32],
}

pub type ConnectedClientsMap = HashMap<String, ConnectedClientEntry>;

pub struct ConnectedClientsTracker {
    connected_clients_cnt: AtomicU64,
    pub connected_clients_map: ConnectedClientsMap,
}

impl ConnectedClientsTracker {
    pub fn new() -> ConnectedClientsTracker {
        // Keeps the mapping between the client common name and the connection handles
        let connected_clients_map: ConnectedClientsMap = HashMap::new();

        ConnectedClientsTracker {
            connected_clients_cnt: AtomicU64::new(0),
            connected_clients_map,
        }
    }

    pub async fn record_client_connected(
        &mut self,
        cn: &str,
        connected_client_entry: ConnectedClientEntry,
    ) {
        let old_value = self
            .connected_clients_cnt
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.add_record_to_connected_clients(cn, connected_client_entry).await;
        debug!("Client connected, connected count: {}", old_value + 1);
    }

    async fn add_record_to_connected_clients(
        &mut self,
        cn: &str,
        connected_client_entry: ConnectedClientEntry,
    ) {
        let existing_record = self
            .connected_clients_map
            .insert(cn.to_owned(), connected_client_entry);
        if let Some(v) = existing_record {
            let _ = v.shutdown_tx.send(()).await;
        }
    }

    pub async fn record_client_disconnected(
        &mut self,
        cn: &str,
        session_id: [u8; 32],
    ) {
        let old_value = self
            .connected_clients_cnt
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.remove_record_from_connected_clients(cn, session_id).await;
        debug!("Client disconnected, connected count: {}", old_value - 1);
    }

    async fn remove_record_from_connected_clients(
        &mut self,
        cn: &str,
        session_id: [u8; 32],
    ) {
        if let Some(entry) = self.connected_clients_map.get(cn) {
            if entry.session_id == session_id {
                self.connected_clients_map.remove(cn);
            }
        }
    }
}
