# Threat Database

## Known Token Stealers

| Name | Type | Detection |
|------|------|-----------|
| AuraThemes | Browser injection | Process name, file hash |
| PirateStealer | Webhook exfil | Discord webhook calls |
| DoeneritNet | Memory scraper | Memory access patterns |
| CortanaTokenGrabber | PowerShell | Script signatures |
| TokenGrabber.py | Python script | File hash, behavior |
| Mercurial Grabber | .NET malware | PE analysis |
| Empyrean | Builder-based | Config patterns |
| Luna Grabber | Node.js | npm package names |
| BlackCap | Multi-target | Process injection |

## Detection Methods

### Signature-Based
Matching against known malware hashes, file names, and code patterns.

### Behavioral
Monitoring for suspicious activity:
- Processes reading Discord's LevelDB
- Unusual network connections from Discord's directory
- Memory scanning targeting Discord's process space
- Clipboard monitoring for token-like strings

### Heuristic
Pattern matching on unknown threats:
- New processes accessing `%APPDATA%/Discord/Local Storage/`
- Webhook POST requests with base64-encoded data
- JavaScript injection into Discord's electron process
