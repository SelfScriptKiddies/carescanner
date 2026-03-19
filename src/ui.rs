// Architecture: a dedicated std::thread handles ALL stderr output.
// Scan tasks only touch atomic counters / message queue — they never
// write to the terminal.  hide()/show() control a `visible` flag;
// the render thread checks it under a shared stderr lock to prevent races.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::io::{Write, stderr};
use std::time::Duration;
use crate::configuration::Config;

const BAR_WIDTH: usize = 40;
const DRAW_INTERVAL_MS: u64 = 50;

struct ProgressBarInner {
    total: u64,
    current: AtomicU64,
    visible: AtomicBool,
    stopped: AtomicBool,
    messages: std::sync::Mutex<Vec<String>>,
}

#[derive(Clone)]
struct CustomProgressBar {
    inner: Arc<ProgressBarInner>,
}

impl CustomProgressBar {
    fn new(total: u64) -> Self {
        let inner = Arc::new(ProgressBarInner {
            total,
            current: AtomicU64::new(0),
            visible: AtomicBool::new(true),
            stopped: AtomicBool::new(false),
            messages: std::sync::Mutex::new(Vec::new()),
        });

        let render_inner = Arc::clone(&inner);
        std::thread::spawn(move || render_loop(render_inner));

        Self { inner }
    }

    fn inc(&self, delta: u64) {
        self.inner.current.fetch_add(delta, Ordering::Relaxed);
    }

    fn set_position(&self, pos: u64) {
        self.inner.current.store(pos, Ordering::Relaxed);
    }

    fn println(&self, msg: &str) {
        self.inner.messages.lock().unwrap().push(msg.to_string());
    }

    fn hide(&self) {
        self.inner.visible.store(false, Ordering::SeqCst);
        // Wait for the render thread to complete its current cycle and see
        // visible=false.  Then clear the bar line under the stderr lock so
        // nothing can sneak a frame in after the clear.
        std::thread::sleep(Duration::from_millis(DRAW_INTERVAL_MS + 20));
        let mut err = stderr().lock();
        let _ = write!(err, "\r\x1b[2K");
        let _ = err.flush();
    }

    fn show(&self) {
        self.inner.visible.store(true, Ordering::SeqCst);
    }

    fn finish(&self) {
        self.inner.visible.store(true, Ordering::SeqCst);
        self.inner.stopped.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(DRAW_INTERVAL_MS * 2));
    }

    fn clear(&self) {
        self.inner.visible.store(false, Ordering::SeqCst);
        self.inner.stopped.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(DRAW_INTERVAL_MS * 2));
    }
}

fn render_loop(inner: Arc<ProgressBarInner>) {
    let mut was_visible = true;

    loop {
        std::thread::sleep(Duration::from_millis(DRAW_INTERVAL_MS));

        let msgs: Vec<String> = {
            let mut q = inner.messages.lock().unwrap();
            if q.is_empty() { Vec::new() } else { q.drain(..).collect() }
        };

        let stopped = inner.stopped.load(Ordering::SeqCst);
        let current = inner.current.load(Ordering::Relaxed);

        // Lock stderr, THEN read visible — serialises with hide().
        let mut err = stderr().lock();
        let visible = inner.visible.load(Ordering::SeqCst);

        if !msgs.is_empty() && was_visible {
            let _ = write!(err, "\r\x1b[2K");
        }
        for msg in &msgs {
            let _ = writeln!(err, "{}", msg);
        }

        if visible {
            write_bar(&mut err, current, inner.total);
            was_visible = true;
        } else if was_visible {
            let _ = write!(err, "\r\x1b[2K");
            was_visible = false;
        }

        let _ = err.flush();
        drop(err);

        if stopped {
            if visible {
                let mut err = stderr().lock();
                let _ = writeln!(err);
                let _ = err.flush();
            }
            break;
        }
    }
}

fn write_bar(err: &mut std::io::StderrLock<'_>, current: u64, total: u64) {
    let pct = if total > 0 {
        (current as f64 / total as f64 * 100.0).min(100.0)
    } else {
        0.0
    };
    let filled = (BAR_WIDTH as f64 * pct / 100.0) as usize;
    let empty = BAR_WIDTH.saturating_sub(filled);

    let _ = write!(
        err,
        "\r\x1b[2K[{}{}] {}/{} ({:.1}%)",
        "█".repeat(filled),
        "░".repeat(empty),
        current,
        total,
        pct,
    );
}

// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Ui {
    disable_progress_bar: bool,
    disable_banner: bool,
    disable_all: bool,
    progress_bar: Option<CustomProgressBar>,
}

impl Ui {
    pub fn new(config: &Config) -> Self {
        Self {
            disable_progress_bar: config.disable_progress_bar,
            disable_banner: config.disable_banner,
            disable_all: config.disable_all,
            progress_bar: None,
        }
    }

    pub fn print_banner(&self) {
        if !self.disable_banner && !self.disable_all {
            println!(r#"
  ____ _____ _______   ____   ______ ____ _____    ____   ____   ___________
_/ ___\\__  \\_  __ \_/ __ \ /  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
\  \___ / __ \|  | \/\  ___/ \___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
 \___  >____  /__|    \___  >____  >\___  >____  /___|  /___|  /\___  >__|
     \/     \/            \/     \/     \/     \/     \/     \/     \/
     When scanner cares about your reports
     "#);
        }
    }

    pub fn init_progress_bar(&mut self, total: u64) {
        if !self.disable_progress_bar && !self.disable_all {
            self.progress_bar = Some(CustomProgressBar::new(total));
        }
    }

    pub fn update_progress_bar(&mut self, current: u64) {
        if let Some(pb) = &self.progress_bar {
            pb.set_position(current);
        }
    }

    pub fn increment_progress_bar(&mut self, delta: u64) {
        if let Some(pb) = &self.progress_bar {
            pb.inc(delta);
        }
    }

    pub fn print_progress_bar(&self, message: String) {
        if let Some(pb) = &self.progress_bar {
            pb.println(&message);
        } else {
            println!("{}", message);
        }
    }

    pub fn hide_progress_bar(&self) {
        if let Some(pb) = &self.progress_bar {
            pb.hide();
        }
    }

    pub fn show_progress_bar(&self) {
        if let Some(pb) = &self.progress_bar {
            pb.show();
        }
    }

    pub fn finish_progress_bar(&mut self) {
        if let Some(pb) = &self.progress_bar {
            pb.finish();
        }
        self.progress_bar = None;
    }

    pub fn clear_progress_bar(&mut self) {
        if let Some(pb) = &self.progress_bar {
            pb.clear();
        }
        self.progress_bar = None;
    }
}
