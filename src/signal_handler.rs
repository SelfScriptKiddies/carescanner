use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

/// Controls pause/resume of scan tasks and detects Ctrl+C via signal-hook.
#[derive(Clone)]
pub struct PauseController {
    paused: Arc<AtomicBool>,
    exit_flag: Arc<AtomicBool>,
    signal_flag: Arc<AtomicBool>,
    resume_notify: Arc<Notify>,
}

impl PauseController {
    pub fn new() -> Self {
        let signal_flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal_flag))
            .expect("Failed to register SIGINT handler");

        Self {
            paused: Arc::new(AtomicBool::new(false)),
            exit_flag: Arc::new(AtomicBool::new(false)),
            signal_flag,
            resume_notify: Arc::new(Notify::new()),
        }
    }

    /// Check and clear the Ctrl+C flag. Called by TermController every tick.
    pub fn signal_caught(&self) -> bool {
        self.signal_flag.swap(false, Ordering::SeqCst)
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.resume_notify.notify_waiters();
    }

    pub fn request_exit(&self) {
        self.exit_flag.store(true, Ordering::SeqCst);
        self.resume();
    }

    pub fn should_exit(&self) -> bool {
        self.exit_flag.load(Ordering::SeqCst)
    }

    pub async fn wait_if_paused(&self) {
        while self.paused.load(Ordering::SeqCst) {
            self.resume_notify.notified().await;
        }
    }
}
