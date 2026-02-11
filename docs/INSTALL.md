# Discord Shield Installation

## From Source
```bash
# Requires Rust 1.70+
git clone https://github.com/bad-antics/nullsec-discord-shield
cd nullsec-discord-shield
cargo build --release
```

## Setup
```bash
# Initialize (creates config and key material)
./target/release/discord-shield init

# Start protection
./target/release/discord-shield protect

# Run as system service
sudo cp discord-shield.service /etc/systemd/system/
sudo systemctl enable --now discord-shield
```

## Supported Platforms
- Linux (x86_64, ARM64)
- Windows 10/11
- macOS 12+
