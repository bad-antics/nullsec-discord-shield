# Getting Started

## Installation

```bash
git clone https://github.com/bad-antics/nullsec-discord-shield
cd nullsec-discord-shield
cargo build --release
```

## Quick Setup

```bash
# Initialize protection
./discord-shield init

# Start protection daemon
./discord-shield protect --daemon

# Check status
./discord-shield status
```

## What It Protects

1. **Discord tokens** — Encrypted at rest and obfuscated in memory
2. **LevelDB storage** — Monitors Discord's local database for unauthorized access
3. **Running processes** — Detects known token stealers and suspicious behavior
4. **Memory access** — Blocks debuggers and memory scanners from reading tokens

## How It Works

When Discord launches:
1. Shield encrypts tokens with AES-256-GCM using machine-bound keys
2. Memory guards activate to prevent process injection
3. File watcher monitors LevelDB for unauthorized reads
4. Process scanner checks for known grabber signatures
