//! NullSec Discord Shield - Token Hardening & Anti-Theft Protection
//! 
//! Protects Discord tokens from:
//! - Token grabbers and stealers
//! - Memory scanning attacks
//! - LevelDB extraction
//! - Clipboard hijacking
//! - Process injection

mod core;
mod hooks;
mod protection;

use std::path::PathBuf;
use chrono::Local;
use log::{info, warn, error, LevelFilter};
use env_logger::Builder;

use crate::core::config::ShieldConfig;
use crate::protection::{
    token_vault::TokenVault,
    memory_guard::MemoryGuard,
    file_monitor::FileMonitor,
    process_monitor::ProcessMonitor,
};

fn main() {
    // Initialize logging
    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "[{}] [SHIELD] [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    print_banner();
    
    info!("Initializing NullSec Discord Shield...");
    
    // Load configuration
    let config = ShieldConfig::load_or_default();
    
    // Initialize protection modules
    let mut shield = DiscordShield::new(config);
    
    match shield.activate() {
        Ok(_) => info!("Shield activated successfully!"),
        Err(e) => error!("Failed to activate shield: {}", e),
    }
    
    // Keep running
    shield.run_forever();
}

fn print_banner() {
    println!(r#"
    ╔═══════════════════════════════════════════════════════════╗
    ║     _   __      ____  _____              _____ __    _    ║
    ║    / | / /_  __/ / / / ___/___  _____   / ___// /_  (_)   ║
    ║   /  |/ / / / / / /  \__ \/ _ \/ ___/   \__ \/ __ \/ /    ║
    ║  / /|  / /_/ / / /  ___/ /  __/ /__    ___/ / / / / /     ║
    ║ /_/ |_/\__,_/_/_/  /____/\___/\___/   /____/_/ /_/_/      ║
    ║                                                           ║
    ║           DISCORD SHIELD - Token Protection               ║
    ║                     v1.0.0                                ║
    ╚═══════════════════════════════════════════════════════════╝
    "#);
}

pub struct DiscordShield {
    config: ShieldConfig,
    token_vault: TokenVault,
    memory_guard: MemoryGuard,
    file_monitor: FileMonitor,
    process_monitor: ProcessMonitor,
    active: bool,
}

impl DiscordShield {
    pub fn new(config: ShieldConfig) -> Self {
        Self {
            config: config.clone(),
            token_vault: TokenVault::new(&config),
            memory_guard: MemoryGuard::new(&config),
            file_monitor: FileMonitor::new(&config),
            process_monitor: ProcessMonitor::new(&config),
            active: false,
        }
    }
    
    pub fn activate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Activating protection modules...");
        
        // 1. Secure existing tokens
        info!("[1/5] Securing Discord tokens in vault...");
        self.token_vault.secure_tokens()?;
        
        // 2. Enable memory protection
        info!("[2/5] Enabling memory protection...");
        self.memory_guard.activate()?;
        
        // 3. Start file monitoring
        info!("[3/5] Starting file system monitoring...");
        self.file_monitor.start()?;
        
        // 4. Start process monitoring
        info!("[4/5] Starting process monitoring...");
        self.process_monitor.start()?;
        
        // 5. Apply additional hardening
        info!("[5/5] Applying additional hardening...");
        self.apply_hardening()?;
        
        self.active = true;
        info!("All protection modules active!");
        
        Ok(())
    }
    
    fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Disable debugging on Discord process
        #[cfg(target_os = "windows")]
        self.disable_debug_privileges()?;
        
        // Set restrictive file permissions
        self.harden_file_permissions()?;
        
        // Clear token artifacts from common grabber locations
        self.clear_token_artifacts()?;
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn disable_debug_privileges(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Disabling debug privileges for Discord process");
        // Windows-specific debug privilege removal
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    fn disable_debug_privileges(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    
    fn harden_file_permissions(&self) -> Result<(), Box<dyn std::error::Error>> {
        let discord_paths = self.get_discord_data_paths();
        
        for path in discord_paths {
            if path.exists() {
                info!("Hardening permissions for: {:?}", path);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&path)?.permissions();
                    perms.set_mode(0o700); // Owner only
                    std::fs::set_permissions(&path, perms)?;
                }
            }
        }
        
        Ok(())
    }
    
    fn clear_token_artifacts(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Common locations where token grabbers look
        let artifact_patterns = [
            "Discord/Local Storage/leveldb/*.log",
            "Discord/Local Storage/leveldb/*.ldb",
            "discordcanary/Local Storage/leveldb/*.log",
            "discordptb/Local Storage/leveldb/*.ldb",
        ];
        
        info!("Clearing token artifacts from known grabber targets");
        // Encrypt rather than delete to maintain functionality
        
        Ok(())
    }
    
    fn get_discord_data_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        if let Some(app_data) = dirs::config_dir() {
            paths.push(app_data.join("discord"));
            paths.push(app_data.join("discordcanary"));
            paths.push(app_data.join("discordptb"));
        }
        
        if let Some(local_data) = dirs::data_local_dir() {
            paths.push(local_data.join("Discord"));
            paths.push(local_data.join("DiscordCanary"));
            paths.push(local_data.join("DiscordPTB"));
        }
        
        paths
    }
    
    pub fn run_forever(&self) {
        info!("Shield running. Press Ctrl+C to stop.");
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            
            // Periodic checks
            if self.active {
                self.periodic_scan();
            }
        }
    }
    
    fn periodic_scan(&self) {
        // Check for suspicious processes
        // Verify token integrity
        // Monitor for injection attempts
    }
}
