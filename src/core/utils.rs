use regex::Regex;
use std::path::PathBuf;

lazy_static::lazy_static! {
    static ref TOKEN_REGEX: Regex = Regex::new(
        r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}"
    ).unwrap();
    
    static ref WEBHOOK_REGEX: Regex = Regex::new(
        r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"
    ).unwrap();
}

pub fn find_tokens_in_text(text: &str) -> Vec<String> {
    TOKEN_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn find_webhooks_in_text(text: &str) -> Vec<String> {
    WEBHOOK_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn get_discord_leveldb_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        if let Some(app_data) = dirs::data_local_dir() {
            paths.push(app_data.join("Discord/Local Storage/leveldb"));
            paths.push(app_data.join("DiscordCanary/Local Storage/leveldb"));
            paths.push(app_data.join("DiscordPTB/Local Storage/leveldb"));
        }
        if let Some(roaming) = dirs::config_dir() {
            paths.push(roaming.join("discord/Local Storage/leveldb"));
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        if let Some(config) = dirs::config_dir() {
            paths.push(config.join("discord/Local Storage/leveldb"));
            paths.push(config.join("discordcanary/Local Storage/leveldb"));
            paths.push(config.join("discordptb/Local Storage/leveldb"));
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        if let Some(app_support) = dirs::data_dir() {
            paths.push(app_support.join("discord/Local Storage/leveldb"));
            paths.push(app_support.join("discordcanary/Local Storage/leveldb"));
        }
    }
    
    paths.into_iter().filter(|p| p.exists()).collect()
}

pub fn is_suspicious_process_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    let suspicious_patterns = [
        "token", "grab", "steal", "logger", "rat", "trojan",
        "keylog", "inject", "hook", "dump", "exfil", "c2",
        "beacon", "cobalt", "mimikatz", "lazagne",
    ];
    
    suspicious_patterns.iter().any(|p| name_lower.contains(p))
}
