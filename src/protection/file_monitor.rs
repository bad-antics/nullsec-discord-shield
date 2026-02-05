use crate::core::config::ShieldConfig;
use log::{info, warn, error};
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

/// Monitors Discord data files for unauthorized access
pub struct FileMonitor {
    config: ShieldConfig,
    watcher_handle: Option<thread::JoinHandle<()>>,
}

impl FileMonitor {
    pub fn new(config: &ShieldConfig) -> Self {
        Self {
            config: config.clone(),
            watcher_handle: None,
        }
    }
    
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.file_monitoring {
            info!("File monitoring disabled in config");
            return Ok(());
        }
        
        let paths = crate::core::utils::get_discord_leveldb_paths();
        if paths.is_empty() {
            warn!("No Discord data paths found to monitor");
            return Ok(());
        }
        
        let (_tx, _rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel();
        
        let config = self.config.clone();
        let handle = thread::spawn(move || {
            let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
                if let Ok(event) = res {
                    Self::handle_event(&event, &config);
                }
            }).expect("Failed to create watcher");
            
            for path in &paths {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    error!("Failed to watch {:?}: {}", path, e);
                }
            }
            
            info!("File monitoring active on {} path(s)", paths.len());
            
            // Keep thread alive
            loop {
                thread::sleep(std::time::Duration::from_secs(1));
            }
        });
        
        self.watcher_handle = Some(handle);
        Ok(())
    }
    
    fn handle_event(event: &Event, config: &ShieldConfig) {
        match &event.kind {
            EventKind::Access(_) => {
                // File was accessed - check if it's suspicious
                for path in &event.paths {
                    if Self::is_sensitive_file(path) {
                        warn!("Sensitive file accessed: {:?}", path);
                        Self::check_accessor(path, config);
                    }
                }
            }
            EventKind::Modify(_) => {
                for path in &event.paths {
                    if Self::is_sensitive_file(path) {
                        warn!("Sensitive file modified: {:?}", path);
                    }
                }
            }
            EventKind::Create(_) => {
                // New file created in Discord directory
                for path in &event.paths {
                    if Self::looks_like_grabber_artifact(path) {
                        error!("Potential grabber artifact detected: {:?}", path);
                        Self::quarantine_file(path);
                    }
                }
            }
            _ => {}
        }
    }
    
    fn is_sensitive_file(path: &PathBuf) -> bool {
        if let Some(filename) = path.file_name() {
            let name = filename.to_string_lossy().to_lowercase();
            return name.ends_with(".ldb") || 
                   name.ends_with(".log") ||
                   name.contains("token") ||
                   name.contains("local storage");
        }
        false
    }
    
    fn looks_like_grabber_artifact(path: &PathBuf) -> bool {
        if let Some(filename) = path.file_name() {
            let name = filename.to_string_lossy().to_lowercase();
            let suspicious = ["token", "grab", "steal", "dump", "exfil", "webhook"];
            return suspicious.iter().any(|s| name.contains(s));
        }
        false
    }
    
    fn check_accessor(_path: &PathBuf, _config: &ShieldConfig) {
        // Check which process accessed the file
        // If not Discord or whitelisted, alert!
        
        #[cfg(target_os = "linux")]
        {
            // Use lsof or /proc to check file handles
        }
        
        #[cfg(target_os = "windows")]
        {
            // Use handle.exe or NtQuerySystemInformation
        }
    }
    
    fn quarantine_file(path: &PathBuf) {
        info!("Quarantining suspicious file: {:?}", path);
        
        let quarantine_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nullsec-discord-shield")
            .join("quarantine");
        
        if let Err(e) = std::fs::create_dir_all(&quarantine_dir) {
            error!("Failed to create quarantine dir: {}", e);
            return;
        }
        
        if let Some(filename) = path.file_name() {
            let dest = quarantine_dir.join(filename);
            if let Err(e) = std::fs::rename(path, &dest) {
                error!("Failed to quarantine file: {}", e);
            } else {
                info!("File quarantined successfully");
            }
        }
    }
}
