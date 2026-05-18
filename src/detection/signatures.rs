use std::collections::HashMap;

pub struct SignatureDatabase {
    signatures: HashMap<String, VulnSignature>,
}

#[derive(Clone, Debug)]
pub struct VulnSignature {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub pattern: String,
    pub description: String,
    pub remediation: String,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
        };
        
        db.load_default_signatures();
        db
    }

    fn load_default_signatures(&mut self) {
        let sigs = vec![
            VulnSignature {
                id: "OXIDE-001".to_string(),
                name: "Apache Struts RCE".to_string(),
                severity: "Critical".to_string(),
                pattern: r"Struts".to_string(),
                description: "Apache Struts framework detected".to_string(),
                remediation: "Update to latest version".to_string(),
            },
            VulnSignature {
                id: "OXIDE-002".to_string(),
                name: "WordPress Version Disclosure".to_string(),
                severity: "Low".to_string(),
                pattern: r"wp-content|wordpress".to_string(),
                description: "WordPress installation detected".to_string(),
                remediation: "Hide WordPress version".to_string(),
            },
            VulnSignature {
                id: "OXIDE-003".to_string(),
                name: "Drupal CMS Detected".to_string(),
                severity: "Info".to_string(),
                pattern: r"drupal|Drupal".to_string(),
                description: "Drupal CMS detected".to_string(),
                remediation: "Keep updated".to_string(),
            },
            VulnSignature {
                id: "OXIDE-004".to_string(),
                name: "Jenkins Instance".to_string(),
                severity: "High".to_string(),
                pattern: r"Jenkins| Hudson".to_string(),
                description: "Jenkins CI server detected".to_string(),
                remediation: "Enable authentication".to_string(),
            },
            VulnSignature {
                id: "OXIDE-005".to_string(),
                name: "Docker Registry".to_string(),
                severity: "High".to_string(),
                pattern: r"docker-registry|Docker Distribution".to_string(),
                description: "Docker registry exposed".to_string(),
                remediation: "Add authentication".to_string(),
            },
        ];

        for sig in sigs {
            self.signatures.insert(sig.id.clone(), sig);
        }
    }

    pub fn all(&self) -> &HashMap<String, VulnSignature> {
        &self.signatures
    }

    pub fn add(&mut self, sig: VulnSignature) {
        self.signatures.insert(sig.id.clone(), sig);
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        Self {
            signatures: self.signatures.clone(),
        }
    }
}
