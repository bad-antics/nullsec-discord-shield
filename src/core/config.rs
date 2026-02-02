use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Enable memory protection
    pub memory_protection: bool,
    /// Enable file monitoring
    pub file_monitoring: bool,
    /// Enable process monitoring
    pub process_monitoring: bool,
    /// Enable token encryption in vault
    pub token_vault: bool,
    /// Block known token grabber processes
    pub block_grabbers: bool,
    /// Alert on suspicious activity
    pub alerts_enabled: bool,
    /// Custom protected paths
    pub protected_paths: Vec<PathBuf>,
    /// Whitelist process names
    pub whitelisted_processes: Vec<String>,
    /// Known token grabber signatures
    pub grabber_signatures: Vec<String>,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            memory_protection: true,
            file_monitoring: true,
            process_monitoring: true,
            token_vault: true,
            block_grabbers: true,
            alerts_enabled: true,
            protected_paths: Vec::new(),
            whitelisted_processes: vec![
                "Discord.exe".into(),
                "DiscordCanary.exe".into(),
                "DiscordPTB.exe".into(),
                "discord".into(),
            ],
            grabber_signatures: vec![
                // Known token grabber patterns
                "token".into(),
                "grabber".into(),
                "stealer".into(),
                "logger".into(),
                "webhook".into(),
                "exfil".into(),
            ],
        }
    }
}

impl ShieldConfig {
    pub fn load_or_default() -> Self {
        let config_path = dirs::config_dir()
            .map(|p| p.join("nullsec-discord-shield").join("config.json"));
        
        if let Some(path) = config_path {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(config) = serde_json::from_str(&content) {
                        return config;
                    }
                }
            }
        }
        
        Self::default()
    }
    
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_dir = dirs::config_dir()
            .ok_or("Could not find config directory")?
            .join("nullsec-discord-shield");
        
        std::fs::create_dir_all(&config_dir)?;
        let config_path = config_dir.join("config.json");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, content)?;
        
        Ok(())
    }
}
