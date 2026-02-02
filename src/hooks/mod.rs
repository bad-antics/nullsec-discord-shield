//! API Hooks for enhanced protection
//! Intercepts system calls to prevent token theft

#[cfg(target_os = "windows")]
pub mod windows_hooks;

#[cfg(target_os = "linux")]
pub mod linux_hooks;
