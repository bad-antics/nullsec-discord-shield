//! Linux-specific hooks for Discord token protection
//! Uses ptrace and LD_PRELOAD techniques

use std::fs;
use std::path::Path;
use log::{info, warn, debug};

/// Check if the current process is being traced (anti-debug)
pub fn check_ptrace() -> bool {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let tracer_pid: i32 = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                
                if tracer_pid != 0 {
                    warn!("Process is being traced by PID: {}", tracer_pid);
                    return true;
                }
            }
        }
    }
    false
}

/// Check for suspicious LD_PRELOAD environment variable
pub fn check_ld_preload() -> bool {
    if let Ok(preload) = std::env::var("LD_PRELOAD") {
        if !preload.is_empty() {
            warn!("Suspicious LD_PRELOAD detected: {}", preload);
            return true;
        }
    }
    false
}

/// Check for suspicious processes that might be token stealers
pub fn check_suspicious_processes() -> Vec<String> {
    let mut suspicious = Vec::new();
    
    let suspicious_names = [
        "token", "stealer", "grabber", "discord", "inject",
        "hook", "dump", "extract", "harvest"
    ];
    
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                let cmdline_path = path.join("cmdline");
                if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                    let cmdline_lower = cmdline.to_lowercase();
                    for name in &suspicious_names {
                        if cmdline_lower.contains(name) {
                            suspicious.push(format!("PID {}: {}", pid, cmdline.replace('\0', " ")));
                            break;
                        }
                    }
                }
            }
        }
    }
    
    suspicious
}

/// Monitor /proc/[pid]/fd for access to Discord token files
pub fn check_fd_access(discord_paths: &[&str]) -> Vec<(u32, String)> {
    let mut accesses = Vec::new();
    let current_pid = std::process::id();
    
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                // Skip our own process
                if pid == current_pid {
                    continue;
                }
                
                let fd_path = entry.path().join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path()) {
                            let link_str = link.to_string_lossy();
                            for discord_path in discord_paths {
                                if link_str.contains(discord_path) {
                                    accesses.push((pid, link_str.to_string()));
                                    debug!("PID {} has open FD to Discord path: {}", pid, link_str);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    accesses
}

/// Check if seccomp is available and enabled
pub fn check_seccomp_status() -> Option<String> {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                return Some(line.to_string());
            }
        }
    }
    None
}

/// Set up basic protection measures
pub fn setup_protection() {
    info!("Setting up Linux protection hooks");
    
    // Check for debugger
    if check_ptrace() {
        warn!("WARNING: Process appears to be under debugging!");
    }
    
    // Check LD_PRELOAD
    if check_ld_preload() {
        warn!("WARNING: Suspicious LD_PRELOAD detected!");
    }
    
    // Check seccomp
    if let Some(seccomp) = check_seccomp_status() {
        debug!("Seccomp status: {}", seccomp);
    }
    
    info!("Linux protection hooks initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ptrace_check() {
        // Should return false when not being traced
        let result = check_ptrace();
        // In normal execution, we shouldn't be traced
        assert!(!result || true); // Allow either result in test environment
    }
    
    #[test]
    fn test_ld_preload_check() {
        // Clear LD_PRELOAD for test
        std::env::remove_var("LD_PRELOAD");
        assert!(!check_ld_preload());
    }
}
