use std::net::IpAddr;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub enum Port {
    Open(u16),
    Closed(u16)
    // Filtered is the default state
}

pub struct AppState {
    // Current results
    results: Mutex<HashMap<IpAddr, Vec<Port>>>,
    port_scanned: Mutex<u64>,

    // Application restoreable state info
}

