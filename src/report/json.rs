use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::detection::analyzer::Finding;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub scan_info: ScanInfo,
    pub findings: Vec<FindingJson>,
    pub statistics: Statistics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanInfo {
    pub target: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingJson {
    pub url: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Statistics {
    pub total_findings: usize,
    pub by_severity: HashMap<String, usize>,
}

impl JsonReport {
    pub fn from_findings(target: &str, findings: &[Finding]) -> Self {
        let finding_jsons: Vec<FindingJson> = findings
            .iter()
            .map(|f| FindingJson {
                url: f.url.clone(),
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                description: f.description.clone(),
                evidence: f.evidence.clone(),
                remediation: f.remediation.clone(),
            })
            .collect();

        let mut by_severity: HashMap<String, usize> = HashMap::new();
        for finding in findings {
            let sev = format!("{:?}", finding.severity);
            *by_severity.entry(sev).or_insert(0) += 1;
        }

        Self {
            scan_info: ScanInfo {
                target: target.to_string(),
                start_time: String::new(),
                end_time: String::new(),
                duration_seconds: 0,
            },
            findings: finding_jsons,
            statistics: Statistics {
                total_findings: findings.len(),
                by_severity,
            },
        }
    }
}
