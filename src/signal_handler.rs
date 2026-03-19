use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{Write, BufRead};
use tokio::sync::Notify;
use tokio::sync::oneshot;

use crate::appstate::AppStateManager;
use crate::configuration::Config;
use crate::ui::Ui;

#[derive(Clone)]
pub struct PauseController {
    paused: Arc<AtomicBool>,
    exit_flag: Arc<AtomicBool>,
    resume_notify: Arc<Notify>,
}

impl PauseController {
    pub fn new() -> Self {
        Self {
            paused: Arc::new(AtomicBool::new(false)),
            exit_flag: Arc::new(AtomicBool::new(false)),
            resume_notify: Arc::new(Notify::new()),
        }
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

enum PauseMenuChoice {
    Continue,
    SaveResults,
    ExitWithSave,
    ExitWithoutSave,
}

fn show_pause_menu() -> PauseMenuChoice {
    loop {
        println!("  1) Continue scan");
        println!("  2) Save results");
        println!("  3) Exit (save results)");
        println!("  4) Exit (without saving)");
        print!("> ");
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        match std::io::stdin().lock().read_line(&mut input) {
            // EINTR (Ctrl+C during read) or EOF — re-display menu, do NOT resume.
            Err(_) | Ok(0) => {
                println!();
                continue;
            }
            Ok(_) => {}
        }

        match input.trim() {
            "1" => return PauseMenuChoice::Continue,
            "2" => return PauseMenuChoice::SaveResults,
            "3" => return PauseMenuChoice::ExitWithSave,
            "4" => return PauseMenuChoice::ExitWithoutSave,
            _ => println!("Invalid choice, try again.\n"),
        }
    }
}

pub fn spawn_signal_handler(
    pause_controller: PauseController,
    app_state_manager: Arc<AppStateManager>,
    config: Arc<Config>,
    ui: Ui,
    exit_tx: Option<oneshot::Sender<()>>,
) {
    let mut exit_tx = exit_tx;

    tokio::spawn(async move {
        // Timestamp of last resume — used to debounce stale signals.
        let mut last_resume = std::time::Instant::now();

        loop {
            tokio::signal::ctrl_c().await.expect("Failed to listen for CTRL+C");

            // Debounce: if a signal arrives within 500ms of the last resume,
            // it's likely a stale signal from a Ctrl+C that interrupted
            // read_line during the menu.  Ignore it.
            if last_resume.elapsed() < std::time::Duration::from_millis(500) {
                continue;
            }

            pause_controller.pause();
            ui.hide_progress_bar();

            println!("\nScan paused (CTRL+C)\n");

            let should_exit = loop {
                match show_pause_menu() {
                    PauseMenuChoice::Continue => {
                        break false;
                    }
                    PauseMenuChoice::SaveResults => {
                        let state = app_state_manager.get_current_state_sync();
                        match state.save_to_file(&config) {
                            Ok(path) => println!("Results saved to: {}", path),
                            Err(e) => eprintln!("Error saving results: {}", e),
                        }
                    }
                    PauseMenuChoice::ExitWithSave => {
                        let state = app_state_manager.get_current_state_sync();
                        match state.save_to_file(&config) {
                            Ok(path) => println!("Results saved to: {}", path),
                            Err(e) => eprintln!("Error saving results: {}", e),
                        }
                        // Save resume file (plain text list of scanned hosts)
                        if let Err(e) = state.save_resume_file("carescanner.resume") {
                            eprintln!("Error saving resume file: {}", e);
                        }
                        break true;
                    }
                    PauseMenuChoice::ExitWithoutSave => {
                        break true;
                    }
                }
            };

            if should_exit {
                pause_controller.request_exit();
                if let Some(tx) = exit_tx.take() {
                    let _ = tx.send(());
                }
                return;
            }

            // Re-enable progress bar and resume scan.
            ui.show_progress_bar();
            pause_controller.resume();
            last_resume = std::time::Instant::now();
        }
    });
}
