use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use crate::modes::{Target, PortStatus};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub enum Port {
    Open(u16),
    Closed(u16)
    // Filtered is the default state
}

// AppState - no mutex needed since only one task accesses this
#[derive(Debug, Clone)]
pub struct AppState {
    // Current results
    results: HashMap<String, Vec<Port>>,
    port_scanned: u64,
}

/// Manager for the app state (mpsc channel)
pub struct AppStateManager {
    app_state: Arc<Mutex<AppState>>,
    results_sender: UnboundedSender<(Target, PortStatus)>,
    processor_handle: Option<JoinHandle<()>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            port_scanned: 0,
        }
    }

    /// Add result to the state (only called from the manager task)
    pub fn add_result(&mut self, target: Target, port_status: PortStatus) {
        self.port_scanned += 1;

        let port = match port_status {
            PortStatus::Open => Port::Open(target.port),
            PortStatus::Closed => Port::Closed(target.port),
            PortStatus::Filtered => return, // Skip filtered ports
        };
        
        let port_vector = self.results.entry(target.ip).or_insert(vec![]);
        port_vector.push(port);
    }

    /// Get current scan statistics
    pub fn get_port_scanned_count(&self) -> u64 {
        self.port_scanned
    }

    /// Get current results
    pub fn get_results(&self) -> &HashMap<String, Vec<Port>> {
        &self.results
    }

    /// Get mutable results for advanced operations
    pub fn get_results_mut(&mut self) -> &mut HashMap<String, Vec<Port>> {
        &mut self.results
    }
}

impl AppStateManager {
    pub fn new() -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let app_state = Arc::new(Mutex::new(AppState::new()));
        let app_state_clone = Arc::clone(&app_state);
        
        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            while let Some((target, port_status)) = receiver.recv().await {
                let mut state = app_state_clone.lock().await;
                state.add_result(target, port_status);
            }
        });
        
        Self {
            app_state,
            results_sender: sender,
            processor_handle: Some(processor_handle),
        }
    }

    pub fn get_results_sender(&self) -> UnboundedSender<(Target, PortStatus)> {
        self.results_sender.clone()
    }

    // Get current state (non-blocking access to results)
    pub async fn get_current_state(&self) -> AppState {
        self.app_state.lock().await.clone()
    }

    // Get final state
    pub async fn finish(self) -> AppState {
        // Just return current state - processor will continue in background
        // until all senders are dropped naturally
        self.app_state.lock().await.clone()
    }
}


