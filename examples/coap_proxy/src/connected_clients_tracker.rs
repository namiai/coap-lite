use std::sync::atomic::AtomicU64;

pub struct ConnectedClientsTracker {
    connected_clients_cnt: AtomicU64,
}

impl ConnectedClientsTracker {
    pub fn new() -> ConnectedClientsTracker {
        ConnectedClientsTracker {
            connected_clients_cnt: AtomicU64::new(0),
        }
    }

    pub fn record_client_connected(&self) {
        let old_value = self
            .connected_clients_cnt
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Client connected, connected count: {}", old_value + 1);
    }

    pub fn record_client_disconnected(&self) {
        let old_value = self
            .connected_clients_cnt
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Client disconnected, connected count: {}", old_value - 1);
    }
}
