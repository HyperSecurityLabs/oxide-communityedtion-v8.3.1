use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::RwLock;

use crate::detection::analyzer::Finding;
use crate::http::response::HttpResponse;

/// Plugin system for custom vulnerability checks
pub struct PluginManager {
    plugins: RwLock<HashMap<String, Box<dyn VulnPlugin>>>,
    enabled_plugins: RwLock<Vec<String>>,
}

/// Trait for vulnerability detection plugins
pub trait VulnPlugin: Send + Sync + std::any::Any {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// Plugin version
    fn version(&self) -> &str;
    
    /// Plugin description
    fn description(&self) -> &str;
    
    /// Plugin author
    fn author(&self) -> &str;
    
    /// Check if plugin applies to this response
    fn applies(&self, response: &HttpResponse) -> bool;
    
    /// Run the vulnerability check
    fn check(&self, response: &HttpResponse) -> Vec<Finding>;
    
    /// Get plugin configuration
    fn config(&self) -> HashMap<String, String>;
    
    /// Update plugin configuration
    fn set_config(&mut self, key: &str, value: &str);
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            enabled_plugins: RwLock::new(Vec::new()),
        }
    }

    /// Register a new plugin
    pub async fn register_plugin(&self, plugin: Box<dyn VulnPlugin>) -> Result<()> {
        let name = plugin.name().to_string();
        let mut plugins = self.plugins.write().await;
        
        if plugins.contains_key(&name) {
            return Err(anyhow::anyhow!("Plugin '{}' already registered", name));
        }
        
        println!("[PLUGIN] Registered: {} v{} by {}", 
            name, plugin.version(), plugin.author());
        
        plugins.insert(name.clone(), plugin);
        
        // Enable by default
        let mut enabled = self.enabled_plugins.write().await;
        enabled.push(name);
        
        Ok(())
    }

    /// Unregister a plugin
    pub async fn unregister_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        plugins.remove(name);
        
        let mut enabled = self.enabled_plugins.write().await;
        enabled.retain(|n| n != name);
        
        println!("[PLUGIN] Unregistered: {}", name);
        Ok(())
    }

    /// Enable a plugin
    pub async fn enable_plugin(&self, name: &str) -> Result<()> {
        let plugins = self.plugins.read().await;
        if !plugins.contains_key(name) {
            return Err(anyhow::anyhow!("Plugin '{}' not found", name));
        }
        
        let mut enabled = self.enabled_plugins.write().await;
        if !enabled.contains(&name.to_string()) {
            enabled.push(name.to_string());
            println!("[PLUGIN] Enabled: {}", name);
        }
        
        Ok(())
    }

    /// Disable a plugin
    pub async fn disable_plugin(&self, name: &str) -> Result<()> {
        let mut enabled = self.enabled_plugins.write().await;
        enabled.retain(|n| n != name);
        println!("[PLUGIN] Disabled: {}", name);
        Ok(())
    }

    /// Run all enabled plugins against a response
    pub async fn run_plugins(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        for plugin_name in enabled.iter() {
            if let Some(plugin) = plugins.get(plugin_name) {
                if plugin.applies(response) {
                    let plugin_findings = plugin.check(response);
                    findings.extend(plugin_findings);
                }
            }
        }
        
        findings
    }

    /// Get list of all registered plugins
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        plugins.values()
            .map(|p| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
                description: p.description().to_string(),
                author: p.author().to_string(),
                enabled: enabled.contains(&p.name().to_string()),
            })
            .collect()
    }

    /// Get plugin by name
    pub async fn get_plugin(&self, name: &str) -> Option<Box<dyn VulnPlugin>> {
        let plugins = self.plugins.read().await;
        if let Some(plugin) = plugins.get(name) {
            // Return plugin info
            let _ = plugin.name(); // Access plugin to use the variable
        }
        drop(plugins);
        // Note: This is a simplified version - in real implementation
        // you'd need Arc<Mutex<>> or similar for shared ownership
        None
    }

    /// Load plugin from dynamic library file (.so/.dll/.dylib)
    pub async fn load_from_file(&self, path: &Path) -> Result<()> {
        use libloading::{Library, Symbol};
        use std::ffi::OsStr;
        
        if !path.exists() {
            return Err(anyhow::anyhow!("Plugin file does not exist: {:?}", path));
        }
        
        // Check file extension
        let ext = path.extension().and_then(OsStr::to_str);
        let is_valid_ext = matches!(ext, Some("so") | Some("dll") | Some("dylib"));
        
        if !is_valid_ext {
            return Err(anyhow::anyhow!(
                "Invalid plugin file extension. Expected .so, .dll, or .dylib, got {:?}",
                ext
            ));
        }
        
        println!("[PLUGIN] Loading dynamic library: {:?}", path);
        
        // Load the library
        let lib = unsafe { Library::new(path) }
            .map_err(|e| anyhow::anyhow!("Failed to load library: {}", e))?;
        
        // Look for the plugin creation symbol
        type CreatePluginFn = unsafe fn() -> *mut dyn VulnPlugin;
        
        let create_plugin: Symbol<CreatePluginFn> = unsafe {
            lib.get(b"create_plugin\0")
                .map_err(|e| anyhow::anyhow!("Failed to find 'create_plugin' symbol: {}", e))?
        };
        
        // Create the plugin instance
        let plugin_ptr = unsafe { (create_plugin)() };
        if plugin_ptr.is_null() {
            return Err(anyhow::anyhow!("Plugin creation returned null pointer"));
        }
        
        // Convert to Box (this is safe because the plugin was allocated by the library)
        let plugin: Box<dyn VulnPlugin> = unsafe { Box::from_raw(plugin_ptr) };
        
        let plugin_name = plugin.name().to_string();
        println!("[PLUGIN] Successfully loaded plugin: {} v{}", 
            plugin_name, plugin.version());
        
        // Register the plugin
        self.register_plugin(plugin).await?;
        
        // Note: We intentionally leak the library handle to keep it loaded
        // In production, you'd use a proper plugin manager with lifetime management
        std::mem::forget(lib);
        
        Ok(())
    }

    /// Get plugin statistics
    pub async fn get_stats(&self) -> PluginStats {
        let plugins = self.plugins.read().await;
        let enabled = self.enabled_plugins.read().await;
        
        PluginStats {
            total: plugins.len(),
            enabled: enabled.len(),
            disabled: plugins.len() - enabled.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct PluginStats {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
}

/// Example built-in plugin for detecting missing security headers
pub struct SecurityHeadersPlugin {
    config: HashMap<String, String>,
}

impl SecurityHeadersPlugin {
    pub fn new() -> Self {
        let mut config = HashMap::new();
        config.insert("severity".to_string(), "Medium".to_string());
        Self { config }
    }
}

impl VulnPlugin for SecurityHeadersPlugin {
    fn name(&self) -> &str {
        "security-headers"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)"
    }

    fn author(&self) -> &str {
        "OXIDE Team"
    }

    fn applies(&self, _response: &HttpResponse) -> bool {
        true // Applies to all responses
    }

    fn check(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        let headers: HashMap<String, String> = response.headers.iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();
        
        // Check required security headers
        let required_headers = vec![
            ("content-security-policy", "Missing Content-Security-Policy header"),
            ("strict-transport-security", "Missing HSTS header"),
            ("x-frame-options", "Missing X-Frame-Options header (clickjacking protection)"),
            ("x-content-type-options", "Missing X-Content-Type-Options header"),
            ("referrer-policy", "Missing Referrer-Policy header"),
            ("permissions-policy", "Missing Permissions-Policy header"),
        ];
        
        for (header, description) in required_headers {
            if !headers.contains_key(header) {
                findings.push(
                    crate::detection::analyzer::Finding::new(
                        "",
                        crate::detection::analyzer::Severity::Medium,
                        &format!("Missing Security Header: {}", header),
                        description,
                    )
                );
            }
        }
        
        findings
    }

    fn config(&self) -> HashMap<String, String> {
        self.config.clone()
    }

    fn set_config(&mut self, key: &str, value: &str) {
        self.config.insert(key.to_string(), value.to_string());
    }
}

/// Example plugin for detecting information disclosure
pub struct InfoDisclosurePlugin {
    config: HashMap<String, String>,
}

impl InfoDisclosurePlugin {
    pub fn new() -> Self {
        let mut config = HashMap::new();
        config.insert("severity".to_string(), "Low".to_string());
        Self { config }
    }
}

impl VulnPlugin for InfoDisclosurePlugin {
    fn name(&self) -> &str {
        "info-disclosure"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects information disclosure in headers and response body"
    }

    fn author(&self) -> &str {
        "OXIDE Team"
    }

    fn applies(&self, _response: &HttpResponse) -> bool {
        true
    }

    fn check(&self, response: &HttpResponse) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check Server header for version disclosure
        if let Some(server) = response.headers.get("Server") {
            if server.chars().any(|c| c.is_ascii_digit()) {
                findings.push(
                    crate::detection::analyzer::Finding::new(
                        "",
                        crate::detection::analyzer::Severity::Low,
                        "Server Version Disclosure",
                        &format!("Server header reveals version information: {}", server),
                    )
                );
            }
        }
        
        // Check X-Powered-By
        if response.headers.contains_key("X-Powered-By") {
            findings.push(
                crate::detection::analyzer::Finding::new(
                    "",
                    crate::detection::analyzer::Severity::Low,
                    "Technology Disclosure",
                    "X-Powered-By header reveals backend technology",
                )
            );
        }
        
        findings
    }

    fn config(&self) -> HashMap<String, String> {
        self.config.clone()
    }

    fn set_config(&mut self, key: &str, value: &str) {
        self.config.insert(key.to_string(), value.to_string());
    }
}
