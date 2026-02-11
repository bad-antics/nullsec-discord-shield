# Configuration Reference

## Config File Location
- Linux: `~/.config/discord-shield/config.toml`
- Windows: `%APPDATA%\discord-shield\config.toml`
- macOS: `~/Library/Application Support/discord-shield/config.toml`

## Options

```toml
[vault]
encryption = "aes-256-gcm"
key_derivation = "argon2id"
auto_lock_timeout = 300  # seconds

[memory]
anti_debug = true
memory_guards = true
injection_detection = true

[file_monitor]
watch_leveldb = true
quarantine_suspicious = true
log_all_access = false

[process_monitor]
scan_interval = 5  # seconds
auto_block = true
whitelist = ["discord", "electron"]

[notifications]
desktop_alerts = true
log_file = "~/.config/discord-shield/shield.log"
```
