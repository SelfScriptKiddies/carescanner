// If you want to add something to the UI, you can do it here.
// Idea is that every UI component must be able to be disabled from CLI-flags.

use indicatif::ProgressBar;
use crate::configuration::Config;

#[derive(Debug, Clone)]
pub struct Ui {
    disable_progress_bar: bool,
    disable_banner: bool,
    disable_all: bool,
    progress_bar: Option<ProgressBar>
}

impl Ui {
    pub fn new(config: &Config) -> Self {
        Self {
            disable_progress_bar: config.disable_progress_bar,
            disable_banner: config.disable_banner,
            disable_all: config.disable_all,
            progress_bar: None
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
            self.progress_bar = Some(ProgressBar::new(total));
        }
    }

    pub fn update_progress_bar(&mut self, current: u64) {
        if let Some(progress_bar) = &mut self.progress_bar {
            progress_bar.set_position(current);
        }
    }

    pub fn increment_progress_bar(&mut self, delta: u64) {
        if let Some(progress_bar) = &mut self.progress_bar {
            progress_bar.inc(delta);
        }
    }

    pub fn print_progress_bar(&self, message: String) {
        if let Some(progress_bar) = &self.progress_bar {
            progress_bar.println(message);
        } else {
            println!("{}", message);
        }
    }

    pub fn finish_progress_bar(&mut self) {
        if let Some(progress_bar) = &mut self.progress_bar {
            progress_bar.finish();
            self.progress_bar = None;
        }
    }
}