use anyhow::Result;
use std::collections::VecDeque;
use std::path::PathBuf;

use crate::detection::analyzer::Finding;
use crate::report::xml::XmlReport;
use crate::report::json::JsonReport;
use crate::report::html::HtmlReport;
use crate::report::csv::CsvReport;

pub struct ReportGenerator {
    findings: VecDeque<Finding>,
    format: String,
}

impl ReportGenerator {
    pub fn new(format: &str) -> Self {
        Self {
            findings: VecDeque::new(),
            format: format.to_string(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push_back(finding);
    }

    pub fn get_findings(&self) -> &VecDeque<Finding> {
        &self.findings
    }

    pub fn count(&self) -> usize {
        self.findings.len()
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        match self.format.as_str() {
            "json" => self.save_json(path),
            "html" => self.save_html(path),
            "csv" => self.save_csv(path),
            "xml" => self.save_xml(path),
            _ => self.save_json(path),
        }
    }

    fn save_json(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let findings: Vec<_> = self.findings.iter().cloned().collect();
        let json_report = JsonReport::from_findings("target", &findings);
        let json = serde_json::to_string_pretty(&json_report)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn save_html(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let mut html = HtmlReport::generate_header("OXIDE Security Scan Report");
        html.push_str(&HtmlReport::generate_table_start());
        
        for finding in &self.findings {
            html.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td></tr>\n",
                finding.severity,
                finding.url,
                finding.title
            ));
        }
        
        html.push_str("</table>");
        html.push_str(&HtmlReport::generate_footer());
        fs::write(path, html)?;
        Ok(())
    }

    fn save_csv(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let mut csv = CsvReport::generate_header();
        
        for finding in &self.findings {
            csv.push_str(&CsvReport::generate_row(
                &finding.url,
                &format!("{:?}", finding.severity),
                &finding.title,
                &finding.description,
                &finding.evidence,
                &finding.remediation,
            ));
        }
        
        fs::write(path, csv)?;
        Ok(())
    }

    fn save_xml(&self, path: &PathBuf) -> Result<()> {
        use std::fs;
        let mut xml = XmlReport::generate_header();
        
        for finding in &self.findings {
            xml.push_str(&XmlReport::generate_finding(
                &finding.url,
                &format!("{:?}", finding.severity),
                &finding.title,
                &finding.description,
                &finding.evidence,
                &finding.remediation,
            ));
        }
        
        xml.push_str(&XmlReport::generate_footer());
        fs::write(path, xml)?;
        Ok(())
    }

    pub fn print_summary(&self) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        // Use get_findings method
        let findings = self.get_findings();
        
        for finding in findings {
            match finding.severity {
                crate::detection::analyzer::Severity::Critical => critical += 1,
                crate::detection::analyzer::Severity::High => high += 1,
                crate::detection::analyzer::Severity::Medium => medium += 1,
                crate::detection::analyzer::Severity::Low => low += 1,
                crate::detection::analyzer::Severity::Info => info += 1,
            }
        }

        println!();
        println!("Scan Summary:");
        println!("  Critical: {}", critical);
        println!("  High: {}", high);
        println!("  Medium: {}", medium);
        println!("  Low: {}", low);
        println!("  Info: {}", info);
        // Use count method
        println!("  Total: {}", self.count());
    }
}

impl Clone for ReportGenerator {
    fn clone(&self) -> Self {
        Self {
            findings: self.findings.clone(),
            format: self.format.clone(),
        }
    }
}
