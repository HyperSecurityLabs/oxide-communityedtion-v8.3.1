pub struct CsvReport;

impl CsvReport {
    pub fn generate_header() -> String {
        "URL,Severity,Title,Description,Evidence,Remediation\n".to_string()
    }

    pub fn escape_field(field: &str) -> String {
        let needs_quotes = field.contains(',') || field.contains('"') || field.contains('\n');
        
        if needs_quotes {
            let escaped = field.replace('"', "\"\"");
            format!("\"{}\"", escaped)
        } else {
            field.to_string()
        }
    }

    pub fn generate_row(
        url: &str,
        severity: &str,
        title: &str,
        description: &str,
        evidence: &str,
        remediation: &str,
    ) -> String {
        format!(
            "{},{},{},{},{},{}\n",
            Self::escape_field(url),
            Self::escape_field(severity),
            Self::escape_field(title),
            Self::escape_field(description),
            Self::escape_field(evidence),
            Self::escape_field(remediation)
        )
    }
}
