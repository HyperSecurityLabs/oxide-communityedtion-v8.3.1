use crate::detection::analyzer::Finding;

pub struct Confirm;

impl Confirm {
    pub fn confirm_vulnerability(finding: &Finding) -> bool {
        if finding.title.contains("SQLi") || finding.title.contains("SQL Injection") {
            Self::confirm_sql_injection(finding)
        } else if finding.title.contains("LFI") || finding.title.contains("File Inclusion") {
            Self::confirm_lfi(finding)
        } else if finding.title.contains("XSS") || finding.title.contains("Cross-Site") {
            Self::confirm_xss(finding)
        } else if finding.title.contains("CMDi") || finding.title.contains("Command Injection") {
            Self::confirm_cmdi(finding)
        } else if finding.title.contains("Admin") || finding.title.contains("Panel") {
            Self::confirm_admin_panel(finding)
        } else {
            false
        }
    }

    fn confirm_sql_injection(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        let body = evidence.clone();
        // Real SQLi: evidence must contain actual DB error or SQL syntax
        (body.contains("sql") || body.contains("mysql") || body.contains("postgresql") ||
         body.contains("oracle") || body.contains("odbc") || body.contains("sqlite")) &&
        // AND the response must not be a generic WAF block or 200-OK with no diff
        !body.contains("cf-ray") &&
        !body.contains("cloudflare") &&
        !body.contains("waf") &&
        !body.contains("blocked")
    }

    fn confirm_xss(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        evidence.contains("<script>") ||
        evidence.contains("alert(") ||
        evidence.contains("onerror=") ||
        evidence.contains("onload=") ||
        evidence.contains("javascript:")
    }

    fn confirm_cmdi(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        evidence.contains("uid=") ||
        evidence.contains("gid=") ||
        evidence.contains("bin/bash") ||
        evidence.contains("bin/sh") ||
        evidence.contains("total ") ||
        evidence.contains("directory of")
    }

    fn confirm_lfi(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        evidence.contains("root:x:0:0") ||
        evidence.contains("root:$1$") ||
        evidence.contains("[boot loader]") ||
        evidence.contains("[fonts]") ||
        evidence.contains("extensions")
    }

    fn confirm_admin_panel(finding: &Finding) -> bool {
        finding.url.to_lowercase().contains("/admin") ||
        finding.url.to_lowercase().contains("/login") ||
        finding.url.to_lowercase().contains("/dashboard")
    }

    pub fn reduce_false_positive(findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| Self::confirm_vulnerability(f))
            .collect()
    }
}
