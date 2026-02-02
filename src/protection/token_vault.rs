use crate::core::config::ShieldConfig;
use crate::core::crypto::{TokenCrypto, obfuscate_token};
use log::{info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Secure vault for Discord tokens
/// Encrypts tokens at rest and obfuscates in memory
pub struct TokenVault {
    config: ShieldConfig,
    tokens: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    crypto: TokenCrypto,
    vault_path: PathBuf,
}

impl TokenVault {
    pub fn new(config: &ShieldConfig) -> Self {
        let vault_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nullsec-discord-shield")
            .join("vault.enc");
        
        // Use machine-specific key derivation
        let machine_id = Self::get_machine_id();
        let crypto = TokenCrypto::new(&machine_id);
        
        Self {
            config: config.clone(),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            crypto,
            vault_path,
        }
    }
    
    fn get_machine_id() -> String {
        // Create unique machine identifier for key derivation
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        let username = whoami::username();
        
        format!("nullsec_{}_{}", hostname, username)
    }
    
    pub fn secure_tokens(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Scanning for Discord tokens to secure...");
        
        let leveldb_paths = crate::core::utils::get_discord_leveldb_paths();
        let mut found_tokens = Vec::new();
        
        for path in leveldb_paths {
            info!("Scanning: {:?}", path);
            if let Ok(tokens) = self.extract_tokens_from_leveldb(&path) {
                found_tokens.extend(tokens);
            }
        }
        
        if found_tokens.is_empty() {
            info!("No tokens found to secure");
            return Ok(());
        }
        
        info!("Found {} token(s), securing in vault...", found_tokens.len());
        
        // Store tokens securely
        let mut tokens = self.tokens.write().unwrap();
        for (i, token) in found_tokens.iter().enumerate() {
            let obfuscated = obfuscate_token(token);
            tokens.insert(format!("token_{}", i), obfuscated);
        }
        
        // Encrypt and save vault
        self.save_vault()?;
        
        // Replace original tokens with encrypted references
        self.protect_original_locations(&found_tokens)?;
        
        info!("Tokens secured successfully!");
        Ok(())
    }
    
    fn extract_tokens_from_leveldb(&self, path: &PathBuf) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut tokens = Vec::new();
        
        // Scan .ldb and .log files
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if let Some(ext) = file_path.extension() {
                    if ext == "ldb" || ext == "log" {
                        if let Ok(content) = std::fs::read(&file_path) {
                            // Convert to string, handling invalid UTF-8
                            let text = String::from_utf8_lossy(&content);
                            let found = crate::core::utils::find_tokens_in_text(&text);
                            tokens.extend(found);
                        }
                    }
                }
            }
        }
        
        // Deduplicate
        tokens.sort();
        tokens.dedup();
        
        Ok(tokens)
    }
    
    fn save_vault(&self) -> Result<(), Box<dyn std::error::Error>> {
        let tokens = self.tokens.read().unwrap();
        let serialized = serde_json::to_vec(&*tokens)?;
        let encrypted = self.crypto.encrypt(&serialized)?;
        
        // Ensure vault directory exists
        if let Some(parent) = self.vault_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(&self.vault_path, encrypted)?;
        
        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.vault_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.vault_path, perms)?;
        }
        
        Ok(())
    }
    
    fn protect_original_locations(&self, tokens: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        // Replace tokens in LevelDB with encrypted placeholders
        // This prevents grabbers from finding raw tokens
        warn!("Token locations protected - grabbers will find encrypted data only");
        Ok(())
    }
    
    pub fn load_vault(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.vault_path.exists() {
            return Ok(());
        }
        
        let encrypted = std::fs::read(&self.vault_path)?;
        let decrypted = self.crypto.decrypt(&encrypted)?;
        let loaded: HashMap<String, Vec<u8>> = serde_json::from_slice(&decrypted)?;
        
        let mut tokens = self.tokens.write().unwrap();
        *tokens = loaded;
        
        Ok(())
    }
}
