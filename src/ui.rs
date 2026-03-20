// Terminal Controller: ONE thread owns ALL terminal I/O.
// Everyone else communicates via std::sync::mpsc channel.
// This eliminates all races between progress bar, messages, and menus.

use std::sync::Arc;
use std::sync::mpsc;
use std::io::{Write, BufRead, stderr};
use std::time::Duration;

use crate::appstate::AppStateManager;
use crate::configuration::Config;
use crate::signal_handler::PauseController;

const BAR_WIDTH: usize = 40;
const TICK_MS: u64 = 50;

// --- Public API ---

pub enum TermEvent {
    SetTotal(u64),
    Inc(u64),
    Message(String),
    Finish,
    ExitEarly,
}

#[derive(Clone)]
pub struct TermHandle {
    tx: mpsc::Sender<TermEvent>,
}

impl TermHandle {
    pub fn inc(&self, delta: u64) {
        let _ = self.tx.send(TermEvent::Inc(delta));
    }

    pub fn message(&self, msg: String) {
        let _ = self.tx.send(TermEvent::Message(msg));
    }

    pub fn set_total(&self, total: u64) {
        let _ = self.tx.send(TermEvent::SetTotal(total));
    }

    pub fn finish(&self) {
        let _ = self.tx.send(TermEvent::Finish);
    }

    pub fn exit_early(&self) {
        let _ = self.tx.send(TermEvent::ExitEarly);
    }
}

// --- Internal ---

#[derive(PartialEq)]
enum TermState {
    Scanning,
    Paused,
    Finished,
}

struct TermController {
    rx: mpsc::Receiver<TermEvent>,
    pause_controller: PauseController,
    app_state_manager: Arc<AppStateManager>,
    config: Arc<Config>,
    rt_handle: tokio::runtime::Handle,
    total: u64,
    current: u64,
    state: TermState,
    quiet: bool,
    show_bar: bool,
}

/// Spawn the TermController on a dedicated OS thread.
/// Returns a handle for sending events and a JoinHandle to wait on.
pub fn spawn_term_controller(
    pause_controller: PauseController,
    app_state_manager: Arc<AppStateManager>,
    config: Arc<Config>,
) -> (TermHandle, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let quiet = config.quiet || config.disable_all;
    let show_bar = !config.disable_progress_bar && !config.disable_all;
    let show_banner = !config.disable_banner && !config.disable_all;

    let rt_handle = tokio::runtime::Handle::current();
    let mut controller = TermController {
        rx,
        pause_controller,
        app_state_manager,
        config,
        rt_handle,
        total: 0,
        current: 0,
        state: TermState::Scanning,
        quiet,
        show_bar,
    };

    let join = std::thread::spawn(move || {
        if show_banner {
            controller.print_banner();
        }
        controller.run();
    });

    (TermHandle { tx }, join)
}

impl TermController {
    fn run(&mut self) {
        let tick = Duration::from_millis(TICK_MS);

        loop {
            // Check for Ctrl+C (signal-hook, instant)
            if self.state == TermState::Scanning && self.pause_controller.signal_caught() {
                self.pause_controller.pause();
                self.clear_bar();
                eprintln!("\nScan paused (CTRL+C)\n");
                self.state = TermState::Paused;
                self.run_pause_menu();
                if self.state == TermState::Finished {
                    break;
                }
                continue;
            }

            if self.state == TermState::Finished {
                break;
            }

            // Drain events
            match self.rx.recv_timeout(tick) {
                Ok(event) => {
                    if self.handle_event(event) { break; }
                    // Drain remaining without blocking
                    while let Ok(event) = self.rx.try_recv() {
                        if self.handle_event(event) { break; }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            // Render bar
            if self.state == TermState::Scanning && self.show_bar && self.total > 0 {
                self.draw_bar();
            }
        }
    }

    /// Returns true if the controller should exit.
    fn handle_event(&mut self, event: TermEvent) -> bool {
        match event {
            TermEvent::SetTotal(total) => {
                self.total = total;
                if self.show_bar {
                    self.draw_bar();
                }
            }
            TermEvent::Inc(delta) => {
                self.current += delta;
            }
            TermEvent::Message(msg) => {
                if !self.quiet {
                    let mut err = stderr().lock();
                    let _ = write!(err, "\r\x1b[2K");
                    let _ = writeln!(err, "{}", msg);
                    let _ = err.flush();
                }
            }
            TermEvent::Finish => {
                if self.show_bar && self.total > 0 {
                    self.draw_bar();
                    let mut err = stderr().lock();
                    let _ = writeln!(err);
                    let _ = err.flush();
                }
                self.state = TermState::Finished;
                return true;
            }
            TermEvent::ExitEarly => {
                self.clear_bar();
                self.state = TermState::Finished;
                return true;
            }
        }
        false
    }

    fn run_pause_menu(&mut self) {
        loop {
            eprintln!("  1) Continue scan");
            eprintln!("  2) Save results");
            eprintln!("  3) Exit (save results)");
            eprintln!("  4) Exit (without saving)");
            eprint!("> ");
            let _ = stderr().flush();

            let mut input = String::new();
            match std::io::stdin().lock().read_line(&mut input) {
                Err(_) | Ok(0) => {
                    // EINTR from Ctrl+C during read — clear flag, re-show menu
                    self.pause_controller.signal_caught();
                    eprintln!();
                    continue;
                }
                Ok(_) => {}
            }

            match input.trim() {
                "1" => {
                    self.pause_controller.signal_caught(); // clear stale signals
                    self.pause_controller.resume();
                    self.state = TermState::Scanning;
                    return;
                }
                "2" => {
                    let state = self.get_app_state();
                    match state.save_to_file(&self.config) {
                        Ok(path) => eprintln!("Results saved to: {}", path),
                        Err(e) => eprintln!("Error saving results: {}", e),
                    }
                }
                "3" => {
                    let state = self.get_app_state();
                    match state.save_to_file(&self.config) {
                        Ok(path) => eprintln!("Results saved to: {}", path),
                        Err(e) => eprintln!("Error saving results: {}", e),
                    }
                    if let Err(e) = state.save_resume_file("carescanner.resume") {
                        eprintln!("Error saving resume file: {}", e);
                    }
                    self.pause_controller.request_exit();
                    self.state = TermState::Finished;
                    return;
                }
                "4" => {
                    self.pause_controller.request_exit();
                    self.state = TermState::Finished;
                    return;
                }
                _ => eprintln!("Invalid choice, try again.\n"),
            }
        }
    }

    fn get_app_state(&self) -> crate::appstate::AppState {
        self.rt_handle.block_on(self.app_state_manager.get_current_state())
    }

    fn draw_bar(&self) {
        let pct = if self.total > 0 {
            (self.current as f64 / self.total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let filled = (BAR_WIDTH as f64 * pct / 100.0) as usize;
        let empty = BAR_WIDTH.saturating_sub(filled);

        let mut err = stderr().lock();
        let _ = write!(
            err,
            "\r\x1b[2K[{}{}] {}/{} ({:.1}%)",
            "█".repeat(filled),
            "░".repeat(empty),
            self.current,
            self.total,
            pct,
        );
        let _ = err.flush();
    }

    fn clear_bar(&self) {
        if self.show_bar {
            let mut err = stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }

    fn print_banner(&self) {
        eprintln!(r#"
  ____ _____ _______   ____   ______ ____ _____    ____   ____   ___________
_/ ___\\__  \\_  __ \_/ __ \ /  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
\  \___ / __ \|  | \/\  ___/ \___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
 \___  >____  /__|    \___  >____  >\___  >____  /___|  /___|  /\___  >__|
     \/     \/            \/     \/     \/     \/     \/     \/     \/
     When scanner cares about your reports
     "#);
    }
}
