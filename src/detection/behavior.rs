// ── BehaviorAnalyzer — HyperSecurity_Offensive_Labs / khaninkali ──────────────
// Real-world response profiling engine used by professional red teams to detect
// WAF appliances, fingerprint backend technologies via header/body signatures,
// and identify anomalous responses indicative of successful injection.
//
// Methods in this module are designed for offensive engagements — they feed
// directly into the scanner pipeline to reduce false positives and surface
// bypass opportunities that automated scanners typically miss.

pub struct BehaviorAnalyzer {
    waf_vendors: Vec<(&'static str, Vec<&'static str>)>,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        let mut waf_vendors: Vec<(&'static str, Vec<&'static str>)> = Vec::new();

        waf_vendors.push(("Cloudflare", vec![
            "cf-ray", "__cfduid", "cf-cache-status", "cf-request-id",
            "cf-waf-error", "cloudflare", "cf-challenge",
        ]));
        waf_vendors.push(("AWS WAF", vec![
            "awselb", "x-amzn-requestid", "x-amz-cf-id",
            "x-amz-cf-pop", "x-amzn-ErrorType", "aws-waf-token",
        ]));
        waf_vendors.push(("ModSecurity", vec![
            "mod_security", "NOYB", "OWASP_CRS", "ModSecurity",
            "x-modsec", "x-owasp-crs",
        ]));
        waf_vendors.push(("F5 BIG-IP ASM", vec![
            "BigIP", "F5", "TSessionId", "MRHSHint",
            "MRHInt", "ASM", "x-wa-ident",
        ]));
        waf_vendors.push(("Imperva Incapsula", vec![
            "incap_ses", "incap_vis", "Incapsula", "X-Iinfo",
            "imperva", "visid_incap",
        ]));
        waf_vendors.push(("Akamai", vec![
            "akamai", "ak_bmsc", "bm_sz", "akavpau",
            "abck", "akacd",
        ]));
        waf_vendors.push(("Sucuri", vec![
            "sucuri", "X-Sucuri-ID", "Sucuri-Cloudproxy",
        ]));
        waf_vendors.push(("Radware", vec![
            "radware", "X-RW-", "alteon",
        ]));
        waf_vendors.push(("Palo Alto", vec![
            "PAN-", "x-pan-", "global-protect",
        ]));
        waf_vendors.push(("Fortinet FortiWeb", vec![
            "FortiWeb", "FORTIWAF", "x-forti-",
        ]));
        waf_vendors.push(("Barracuda", vec![
            "barracuda", "x-barracuda-", "BarracudaWAF",
        ]));
        waf_vendors.push(("Citrix NetScaler", vec![
            "netscaler", "NS-CACHE", "Citrix",
        ]));

        Self {
            waf_vendors,
        }
    }

    pub fn detect_error_page(&self, body: &str) -> Option<String> {
        let patterns = [
            ("MySQL Error", &["You have an error in your SQL syntax" as &str, "MySQL server version", "Warning: mysql_", "SQL syntax; check", "mysqli_fetch", "mysql_fetch", "Division by zero in"][..]),
            ("MSSQL Error", &["Microsoft OLE DB", "Microsoft SQL Server", "Unclosed quotation mark", "Incorrect syntax near", "SQL Server Native Client", "OLE DB provider", "Warning: mssql_", "SQLSTATE[23000]"][..]),
            ("PostgreSQL Error", &["PostgreSQL", "pg_query", "pg_exec", "PSQLException", "pg_connect", "Warning: pg_"][..]),
            ("Oracle Error", &["ORA-[0-9]{5}", "Oracle error", "Oracle.*Driver", "Warning: oci_", "OCIParse", "OCIExecute"][..]),
            ("Java Error", &["java.lang", "java.sql", "javax.servlet", "ServletException", "NullPointerException", "Stack trace:", "at java.", "org.apache", "javax.faces"][..]),
            ("Python Error", &["Traceback (most recent call last)", "File \"", "SyntaxError:", "NameError:", "TypeError:", "AttributeError:", "Django", "Flask", "raise_"][..]),
            (".NET Error", &["System.Data.", "System.Web.", "System.NullReference", "System.IndexOutOfRange", ".NET Runtime", "ASP.NET", "Request Validation", "Server Error in"][..]),
            ("PHP Error", &["PHP Fatal error", "PHP Warning", "PHP Notice", "Parse error", "Fatal error: Call to undefined", "Warning: require(", "Warning: include(", "Warning: file_get_contents"][..]),
            ("Ruby Error", &["Ruby on Rails", "ActionController", "ActiveRecord", "SQLite3::", "Rack::", "WEBrick", "NoMethodError", "NameError in"][..]),
            ("Express/Node Error", &["Express", "Node.js", "SyntaxError: Unexpected token", "Cannot find module", "TypeError: Cannot read property", "ReferenceError:"][..]),
            ("Tomcat Error", &["Apache Tomcat", "HTTP Status 404", "type Status report", "JBoss", "WebSphere"][..]),
            ("Nginx Error", &["nginx", "400 Bad Request", "414 Request-URI Too Large", "upstream timed out"][..]),
            ("IIS Error", &["IIS", "Internet Information Services", "ASP_", "Server.CreateObject"][..]),
            ("Generic SQL", &["SQL syntax", "SQLSTATE", "Syntax error", "unrecognized token", "near \"", "syntax error at"][..]),
        ];

        for (tech, signatures) in &patterns {
            for sig in *signatures {
                if body.contains(sig) {
                    return Some(tech.to_string());
                }
            }
        }
        None
    }

    pub fn detect_waf(&self, headers: &[String]) -> Option<String> {
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        for (name, sigs) in &self.waf_vendors {
            for sig in sigs {
                if header_lower.iter().any(|h| h.contains(&sig.to_lowercase())) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    pub fn detect_tech_stack(&self, headers: &[String], body: &str) -> Vec<String> {
        let mut techs = Vec::new();
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        let server_header = header_lower.iter().find(|h| h.starts_with("server:"));
        if let Some(s) = server_header {
            let val = s.trim_start_matches("server:").trim();
            if val.contains("nginx") { techs.push("Nginx".to_string()); }
            if val.contains("apache") { techs.push("Apache".to_string()); }
            if val.contains("iis") || val.contains("microsoft-iis") { techs.push("IIS".to_string()); }
            if val.contains("cloudflare") { techs.push("Cloudflare".to_string()); }
        }

        let powered_by = header_lower.iter().find(|h| h.starts_with("x-powered-by:"));
        if let Some(s) = powered_by {
            let val = s.trim_start_matches("x-powered-by:").trim();
            if val.contains("PHP") { techs.push("PHP".to_string()); }
            if val.contains("ASP.NET") { techs.push("ASP.NET".to_string()); }
            if val.contains("Express") { techs.push("Express".to_string()); }
        }

        if body.contains("wp-content") || body.contains("wp-includes") {
            techs.push("WordPress".to_string());
        }
        if body.contains("Joomla!") || body.contains("com_content") {
            techs.push("Joomla".to_string());
        }
        if body.contains("Drupal") || body.contains("drupal.js") {
            techs.push("Drupal".to_string());
        }
        if body.contains("Shopify") || body.contains("myshopify.com") {
            techs.push("Shopify".to_string());
        }
        if body.contains("Laravel") || body.contains("laravel_session") {
            techs.push("Laravel".to_string());
        }
        if body.contains("Django") || body.contains("csrfmiddlewaretoken") && body.contains("__admin") {
            techs.push("Django".to_string());
        }
        if body.contains("Ruby on Rails") || body.contains("csrf-token") && body.contains("rails") {
            techs.push("Rails".to_string());
        }

        techs.sort();
        techs.dedup();
        techs
    }

}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BehaviorAnalyzer {
    fn clone(&self) -> Self {
        Self {
            waf_vendors: self.waf_vendors.clone(),
        }
    }
}
