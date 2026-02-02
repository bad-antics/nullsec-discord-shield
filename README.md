# NullSec Discord Shield 🛡️

Advanced Discord token hardening and anti-theft protection system.

## Features

### 🔐 Token Vault
- **Encrypted Storage**: Tokens encrypted with AES-256-GCM
- **Memory Obfuscation**: Tokens scrambled in RAM to prevent memory scanning
- **Machine-Bound Keys**: Encryption keys derived from hardware identifiers

### 🧠 Memory Protection
- **Anti-Debug**: Prevents debuggers from attaching to Discord
- **Memory Guards**: Blocks unauthorized memory reads
- **Injection Detection**: Monitors for DLL/SO injection attempts

### 📁 File Monitoring
- **LevelDB Watch**: Real-time monitoring of Discord's token storage
- **Access Logging**: Records all file access attempts
- **Quarantine**: Automatically isolates suspicious files

### 👁️ Process Monitoring
- **Grabber Detection**: Identifies known token stealers
- **Behavioral Analysis**: Detects suspicious process patterns
- **Auto-Block**: Stops malicious processes automatically

## Installation

```bash
# Clone repository
git clone https://github.com/bad-antics/nullsec-discord-shield
cd nullsec-discord-shield

# Build
cargo build --release

# Run
./target/release/discord-shield
```

## Usage

```bash
# Basic usage - starts all protection modules
discord-shield

# Start with specific modules
discord-shield --no-memory    # Disable memory protection
discord-shield --no-files     # Disable file monitoring
discord-shield --no-process   # Disable process monitoring
```

## Configuration

Config file: `~/.config/nullsec-discord-shield/config.json`

```json
{
  "memory_protection": true,
  "file_monitoring": true,
  "process_monitoring": true,
  "token_vault": true,
  "block_grabbers": true,
  "alerts_enabled": true,
  "whitelisted_processes": ["Discord.exe", "discord"],
  "grabber_signatures": ["token", "grabber", "stealer"]
}
```

## How It Works

### Token Protection Flow
1. Scans Discord's LevelDB for existing tokens
2. Encrypts tokens and stores in secure vault
3. Obfuscates tokens in memory with XOR scrambling
4. Monitors for unauthorized access attempts
5. Blocks and logs any detected threats

### Known Grabber Detection
Shield detects and blocks:
- Python token grabbers
- Node.js stealers  
- Webhook exfiltrators
- Memory scanners
- Process injectors

## Supported Platforms

| Platform | Status |
|----------|--------|
| Windows 10/11 | ✅ Full Support |
| Linux | ✅ Full Support |
| macOS | ⚠️ Partial |

## Security Notice

This tool is for **protecting your own accounts**. Use responsibly.

## License

MIT License - Part of NullSec Linux project

---

<p align="center">
<img src="https://img.shields.io/badge/NullSec-Discord_Shield-00ff88?style=for-the-badge">
<img src="https://img.shields.io/badge/Rust-Memory_Safe-000000?style=for-the-badge&logo=rust">
</p>
