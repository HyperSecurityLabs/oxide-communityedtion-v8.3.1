pub struct XmlReport;

impl XmlReport {
    pub fn generate_header() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<scan xmlns="http://oxide.org/schema">
    <metadata>
        <tool>OXIDE</tool>
        <version>1.0.0</version>
    </metadata>
    <findings>
"#.to_string()
    }

    pub fn generate_finding(
        url: &str,
        severity: &str,
        title: &str,
        description: &str,
        evidence: &str,
        remediation: &str,
    ) -> String {
        format!(
        r#"        <finding>
            <url>{}</url>
            <severity>{}</severity>
            <title>{}</title>
            <description>{}</description>
            <evidence>{}</evidence>
            <remediation>{}</remediation>
        </finding>
"#,
            Self::escape_xml(url),
            Self::escape_xml(severity),
            Self::escape_xml(title),
            Self::escape_xml(description),
            Self::escape_xml(evidence),
            Self::escape_xml(remediation)
        )
    }

    pub fn generate_footer() -> String {
        r#"    </findings>
</scan>"#.to_string()
    }

    fn escape_xml(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}
