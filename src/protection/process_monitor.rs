use crate::core::config::ShieldConfig;
use log::{info, warn, error};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// Monitors processes for token grabber behavior
pub struct ProcessMonitor {
    config: ShieldConfig,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
    monitor_handle: Option<thread::JoinHandle<()>>,
}

impl ProcessMonitor {
    pub fn new(config: &ShieldConfig) -> Self {
        Self {
            config: config.clone(),
            blocked_pids: Arc::new(RwLock::new(HashSet::new())),
            monitor_handle: None,
        }
    }
    
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.process_monitoring {
            info!("Process monitoring disabled in config");
            return Ok(());
        }
        
        let config = self.config.clone();
        let blocked_pids = Arc::clone(&self.blocked_pids);
        
        let handle = thread::spawn(move || {
            info!("Process monitoring started");
            
            loop {
                Self::scan_processes(&config, &blocked_pids);
                thread::sleep(Duration::from_secs(5));
            }
        });
        
        self.monitor_handle = Some(handle);
        Ok(())
    }
    
    fn scan_processes(config: &ShieldConfig, blocked_pids: &Arc<RwLock<HashSet<u32>>>) {
        // Get list of running processes
        let processes = Self::get_running_processes();
        
        for (pid, name, cmdline) in processes {
            // Skip whitelisted processes
            if config.whitelisted_processes.iter().any(|w| name.contains(w)) {
                continue;
            }
            
            // Check for suspicious processes
            if Self::is_suspicious_process(&name, &cmdline, config) {
                warn!("Suspicious process detected: {} (PID: {})", name, pid);
                
                if config.block_grabbers {
                    Self::handle_threat(pid, &name, blocked_pids);
                }
            }
        }
    }
    
    fn get_running_processes() -> Vec<(u32, String, String)> {
        let mut processes = Vec::new();
        
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                        let comm_path = entry.path().join("comm");
                        let cmdline_path = entry.path().join("cmdline");
                        
                        let name = std::fs::read_to_string(&comm_path)
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        
                        let cmdline = std::fs::read_to_string(&cmdline_path)
                            .unwrap_or_default()
                            .replace('\0', " ");
                        
                        if !name.is_empty() {
                            processes.push((pid, name, cmdline));
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows process enumeration
            // Use CreateToolhelp32Snapshot or EnumProcesses
        }
        
        processes
    }
    
    fn is_suspicious_process(name: &str, cmdline: &str, config: &ShieldConfig) -> bool {
        let name_lower = name.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();
        
        // Check against known grabber signatures
        for sig in &config.grabber_signatures {
            if name_lower.contains(sig) || cmdline_lower.contains(sig) {
                return true;
            }
        }
        
        // Check for suspicious patterns
        let patterns = [
            "discord.*token",
            "leveldb",
            "local.storage",
            "webhook.*discord",
            "base64.*token",
        ];
        
        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&cmdline_lower) {
                    return true;
                }
            }
        }
        
        // Check for Python/Node scripts accessing Discord paths
        if (name_lower.contains("python") || name_lower.contains("node")) {
            if cmdline_lower.contains("discord") && 
               (cmdline_lower.contains("token") || cmdline_lower.contains("leveldb")) {
                return true;
            }
        }
        
        false
    }
    
    fn handle_threat(pid: u32, name: &str, blocked_pids: &Arc<RwLock<HashSet<u32>>>) {
        let mut blocked = blocked_pids.write().unwrap();
        
        if blocked.contains(&pid) {
            return; // Already handled
        }
        
        error!("THREAT BLOCKED: {} (PID: {})", name, pid);
        
        #[cfg(target_os = "linux")]
        {
            // Send SIGSTOP or SIGKILL
            use std::process::Command;
            let _ = Command::new("kill")
                .args(["-STOP", &pid.to_string()])
                .output();
        }
        
        #[cfg(target_os = "windows")]
        {
            // Use TerminateProcess
        }
        
        blocked.insert(pid);
        
        // Log the threat
        Self::log_threat(pid, name);
    }
    
    fn log_threat(pid: u32, name: &str) {
        let log_dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("nullsec-discord-shield")
            .join("threats");
        
        let _ = std::fs::create_dir_all(&log_dir);
        
        let log_file = log_dir.join("threat_log.txt");
        let entry = format!(
            "[{}] Blocked: {} (PID: {})\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            name,
            pid
        );
        
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            let _ = file.write_all(entry.as_bytes());
        }
    }
}
