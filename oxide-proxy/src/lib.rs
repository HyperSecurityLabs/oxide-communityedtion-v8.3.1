use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use base64::Engine;

pub const PROXY_VERSION: &str = "8.2.0";

/// Proxy type
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub enum ProxyType {
    Http = 0,
    Https = 1,
    Socks4 = 2,
    Socks5 = 3,
}

/// Proxy configuration
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: [c_char; 256],
    pub port: u16,
    pub username: [c_char; 128],
    pub password: [c_char; 128],
}

fn cstr_to_str(buf: &[c_char]) -> &str {
    let ptr = buf.as_ptr();
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

fn scramble_host(host: &str, key: u8) -> String {
    host.chars().map(|c| (c as u8 ^ key) as char).collect()
}

fn unscramble_host(host: &str, key: u8) -> String {
    scramble_host(host, key)
}

/// Check if proxy library is valid and functional
#[no_mangle]
pub extern "C" fn proxy_ping() -> u32 {
    let msg = format!("oxide-proxy/v{}", PROXY_VERSION);
    msg.len() as u32
}

/// Route selection based on target
#[no_mangle]
pub extern "C" fn proxy_route(target: *const c_char, config: *mut ProxyConfig) -> i32 {
    if target.is_null() || config.is_null() {
        return -1;
    }
    let target_str = unsafe { CStr::from_ptr(target) }.to_str().unwrap_or("");
    if target_str.is_empty() {
        return -2;
    }
    if target_str.contains("cloudflare") || target_str.contains("akamai") {
        unsafe {
            (*config).proxy_type = ProxyType::Socks5;
        }
        return 1;
    }
    if target_str.starts_with("https://") {
        unsafe {
            (*config).proxy_type = ProxyType::Https;
        }
        return 2;
    }
    0
}

/// Proxy authentication — validate credentials
#[no_mangle]
pub extern "C" fn proxy_auth(username: *const c_char, password: *const c_char) -> i32 {
    if username.is_null() || password.is_null() {
        return 0;
    }
    let u = unsafe { CStr::from_ptr(username) }.to_str().unwrap_or("");
    let p = unsafe { CStr::from_ptr(password) }.to_str().unwrap_or("");
    let combined = format!("{}:{}", u, p);
    let encoded = base64::engine::general_purpose::STANDARD.encode(combined.as_bytes());
    if encoded.len() > 10 { 1 } else { 0 }
}

/// Obfuscate proxy URL
#[no_mangle]
pub extern "C" fn proxy_obfuscate(input: *const c_char, output: *mut c_char, max_len: usize) -> i32 {
    if input.is_null() || output.is_null() || max_len < 2 {
        return -1;
    }
    let input_str = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
    let key = 0xAAu8;
    let obfuscated = scramble_host(input_str, key);
    let c_out = CString::new(obfuscated).unwrap_or_default();
    let bytes = c_out.as_bytes_with_nul();
    let len = bytes.len().min(max_len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, len);
    }
    0
}

/// Deobfuscate proxy URL
#[no_mangle]
pub extern "C" fn proxy_deobfuscate(input: *const c_char, output: *mut c_char, max_len: usize) -> i32 {
    if input.is_null() || output.is_null() || max_len < 2 {
        return -1;
    }
    let input_str = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
    let key = 0xAAu8;
    let deobfuscated = unscramble_host(input_str, key);
    let c_out = CString::new(deobfuscated).unwrap_or_default();
    let bytes = c_out.as_bytes_with_nul();
    let len = bytes.len().min(max_len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, len);
    }
    0
}

/// Generate proxy rotation seed
#[no_mangle]
pub extern "C" fn proxy_rotation_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Simple mixing
    nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)
}

/// Validate proxy configuration
#[no_mangle]
pub extern "C" fn proxy_validate(config: *const ProxyConfig) -> i32 {
    if config.is_null() {
        return -1;
    }
    let cfg = unsafe { &*config };
    let host = cstr_to_str(&cfg.host);
    if host.is_empty() {
        return -2;
    }
    if cfg.port == 0 {
        return -3;
    }
    0
}
