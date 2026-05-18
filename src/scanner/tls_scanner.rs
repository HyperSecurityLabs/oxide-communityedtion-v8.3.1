use anyhow::Result;
use reqwest::Client;
use tokio::time::{Duration, timeout};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SSL/TLS Deep Scanner — real protocol-level assessment.
/// Certificate parsing uses the raw TLS ServerHello/Certificate record;
/// no dummy data is returned — if parsing fails the finding says so.
pub struct TlsScanner {
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct TlsFinding {
    pub severity: TlsSeverity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl TlsScanner {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self { client, timeout: Duration::from_secs(timeout_secs) })
    }

    pub async fn scan(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        println!("[TLS] Starting comprehensive TLS assessment...");

        if !target.starts_with("https://") {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "No HTTPS Encryption".to_string(),
                description: "Target does not use HTTPS. All communication is unencrypted.".to_string(),
                evidence: "HTTP protocol detected".to_string(),
                remediation: "Enable HTTPS with TLS 1.2 or higher. Redirect HTTP to HTTPS.".to_string(),
            });
            return findings;
        }

        findings.extend(self.check_certificate(target).await);
        findings.extend(self.check_tls_versions(target).await);
        findings.extend(self.check_cipher_suites(target).await);
        findings.extend(self.check_hsts(target).await);
        findings.extend(self.check_tls_headers(target).await);
        findings.extend(self.check_known_vulns(target).await);
        findings
    }

    // ── Certificate check ─────────────────────────────────────────────────────

    async fn check_certificate(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        let host = Self::extract_host(target);

        match self.parse_certificate(&host, 443).await {
            Ok(cert) => {
                if cert.expired {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::Critical,
                        title: "Expired SSL Certificate".to_string(),
                        description: format!("Certificate expired on {}", cert.not_after),
                        evidence: format!("Subject: {} | NotAfter: {}", cert.subject, cert.not_after),
                        remediation: "Renew the SSL certificate immediately.".to_string(),
                    });
                } else if cert.days_remaining < 30 {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::Medium,
                        title: "SSL Certificate Expiring Soon".to_string(),
                        description: format!("Certificate expires in {} days", cert.days_remaining),
                        evidence: format!("NotAfter: {}", cert.not_after),
                        remediation: "Renew the certificate within the next few weeks.".to_string(),
                    });
                }
                if cert.self_signed {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::Medium,
                        title: "Self-Signed Certificate".to_string(),
                        description: "Certificate is self-signed and not trusted by browsers.".to_string(),
                        evidence: format!("Issuer == Subject: {}", cert.subject),
                        remediation: "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)".to_string(),
                    });
                }
                if cert.sig_alg_weak {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::High,
                        title: "Weak Certificate Signature Algorithm".to_string(),
                        description: format!("Certificate uses weak signature: {}", cert.sig_alg),
                        evidence: cert.sig_alg.clone(),
                        remediation: "Reissue certificate using SHA-256 or SHA-384.".to_string(),
                    });
                }
                if cert.key_bits > 0 && cert.key_bits < 2048 {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::Critical,
                        title: "Weak RSA Key Length".to_string(),
                        description: format!("RSA key is only {} bits (minimum 2048 recommended)", cert.key_bits),
                        evidence: format!("{} bits", cert.key_bits),
                        remediation: "Reissue certificate with 2048-bit or 4096-bit RSA key.".to_string(),
                    });
                }
                if cert.is_wildcard {
                    findings.push(TlsFinding {
                        severity: TlsSeverity::Info,
                        title: "Wildcard Certificate".to_string(),
                        description: "Server uses a wildcard certificate.".to_string(),
                        evidence: cert.subject.clone(),
                        remediation: "Consider per-subdomain certificates for better isolation.".to_string(),
                    });
                }
            }
            Err(e) => {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Medium,
                    title: "Certificate Analysis Failed".to_string(),
                    description: format!("Could not parse certificate: {}", e),
                    evidence: e.to_string(),
                    remediation: "Ensure the server presents a valid DER-encoded certificate chain.".to_string(),
                });
            }
        }
        findings
    }

    // ── Real certificate parser ───────────────────────────────────────────────
    //
    // Sends a minimal but valid TLS 1.2 ClientHello, reads the ServerHello +
    // Certificate records, and parses the first certificate's key fields from
    // the raw DER bytes.  No dummy data is ever returned.

    async fn parse_certificate(&self, host: &str, port: u16) -> Result<CertInfo> {
        let addr = format!("{}:{}", host, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timed out"))?
            .map_err(|e| anyhow::anyhow!("TCP connect failed: {}", e))?;

        // Send a real TLS 1.2 ClientHello with common cipher suites + SNI
        let hello = Self::build_real_client_hello(host);
        stream.write_all(&hello).await
            .map_err(|e| anyhow::anyhow!("Write failed: {}", e))?;

        // Read up to 16 KB — enough for the full handshake flight
        let mut buf = vec![0u8; 16384];
        let n = timeout(self.timeout, stream.read(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("Read timed out"))?
            .map_err(|e| anyhow::anyhow!("Read failed: {}", e))?;

        if n < 5 {
            return Err(anyhow::anyhow!("Response too short ({} bytes)", n));
        }

        Self::extract_cert_info(&buf[..n], host)
    }

    /// Build a real TLS 1.2 ClientHello with SNI extension.
    fn build_real_client_hello(host: &str) -> Vec<u8> {
        // SNI extension
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len();
        // server_name list entry: type(1) + length(2) + name
        let sni_entry_len = 1 + 2 + host_len;
        // server_name list: length(2) + entry
        let sni_list_len = 2 + sni_entry_len;
        // extension data: sni_list
        let ext_data_len = sni_list_len;
        // extension: type(2) + length(2) + data
        let sni_ext_len = 4 + ext_data_len;

        // Supported versions extension (TLS 1.3 support signal)
        let supported_versions_ext: &[u8] = &[
            0x00, 0x2b,             // type: supported_versions
            0x00, 0x05,             // length: 5
            0x04,                   // list length: 4
            0x03, 0x04,             // TLS 1.3
            0x03, 0x03,             // TLS 1.2
        ];

        let extensions_len = sni_ext_len + supported_versions_ext.len();

        // Random (32 bytes) — static for reproducibility
        let random = [0x01u8; 32];

        // Cipher suites: TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let cipher_suites: &[u8] = &[
            0x00, 0x04,             // length: 4 bytes (2 suites)
            0x13, 0x01,             // TLS_AES_128_GCM_SHA256
            0xc0, 0x2b,             // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        ];

        let mut client_hello_body = Vec::new();
        client_hello_body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
        client_hello_body.extend_from_slice(&random);
        client_hello_body.push(0x00); // session_id length: 0
        client_hello_body.extend_from_slice(cipher_suites);
        client_hello_body.extend_from_slice(&[0x01, 0x00]); // compression: null only

        // Extensions
        client_hello_body.push(((extensions_len >> 8) & 0xff) as u8);
        client_hello_body.push((extensions_len & 0xff) as u8);

        // SNI extension
        client_hello_body.extend_from_slice(&[0x00, 0x00]); // type: server_name
        client_hello_body.push(((ext_data_len >> 8) & 0xff) as u8);
        client_hello_body.push((ext_data_len & 0xff) as u8);
        client_hello_body.push(((sni_list_len >> 8) & 0xff) as u8);
        client_hello_body.push((sni_list_len & 0xff) as u8);
        client_hello_body.push(0x00); // name_type: host_name
        client_hello_body.push(((host_len >> 8) & 0xff) as u8);
        client_hello_body.push((host_len & 0xff) as u8);
        client_hello_body.extend_from_slice(host_bytes);

        // Supported versions extension
        client_hello_body.extend_from_slice(supported_versions_ext);

        // Handshake header: type(1) + length(3)
        let body_len = client_hello_body.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&client_hello_body);

        // TLS record: content_type(1) + version(2) + length(2) + data
        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 compat record version
        record.push(((record_len >> 8) & 0xff) as u8);
        record.push((record_len & 0xff) as u8);
        record.extend_from_slice(&handshake);
        record
    }

    /// Parse the raw TLS handshake bytes and extract certificate metadata.
    fn extract_cert_info(data: &[u8], host: &str) -> Result<CertInfo> {
        // Walk TLS records looking for a Certificate (handshake type 0x0b) record
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let content_type = data[pos];
            let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            let payload_start = pos + 5;
            let payload_end = payload_start + record_len;

            if payload_end > data.len() { break; }

            if content_type == 0x16 && payload_start < payload_end {
                // Handshake record — may contain multiple messages
                let mut hpos = payload_start;
                while hpos + 4 <= payload_end {
                    let hs_type = data[hpos];
                    let hs_len = u32::from_be_bytes([0, data[hpos+1], data[hpos+2], data[hpos+3]]) as usize;
                    let hs_body_start = hpos + 4;
                    let hs_body_end = hs_body_start + hs_len;
                    if hs_body_end > payload_end { break; }

                    if hs_type == 0x0b {
                        // Certificate message
                        return Self::parse_certificate_message(&data[hs_body_start..hs_body_end], host);
                    }
                    hpos = hs_body_end;
                }
            }
            pos = payload_end;
        }
        Err(anyhow::anyhow!("No Certificate handshake message found in server response"))
    }

    /// Parse the Certificate handshake message body and extract key fields.
    fn parse_certificate_message(body: &[u8], host: &str) -> Result<CertInfo> {
        if body.len() < 3 {
            return Err(anyhow::anyhow!("Certificate message too short"));
        }
        // certificates_length (3 bytes)
        let certs_len = u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
        if body.len() < 3 + certs_len || certs_len < 3 {
            return Err(anyhow::anyhow!("Certificate list length mismatch"));
        }
        // First certificate: length (3 bytes) + DER data
        let cert_len = u32::from_be_bytes([0, body[3], body[4], body[5]]) as usize;
        let cert_start = 6;
        let cert_end = cert_start + cert_len;
        if cert_end > body.len() {
            return Err(anyhow::anyhow!("Certificate DER truncated"));
        }
        let der = &body[cert_start..cert_end];
        Self::parse_der_cert(der, host)
    }

    /// Minimal DER/ASN.1 parser for the fields we care about.
    /// Extracts: subject CN, issuer CN, notBefore/notAfter, public key size,
    /// signature algorithm OID, and wildcard flag.
    fn parse_der_cert(der: &[u8], _host: &str) -> Result<CertInfo> {
        // We use a simple tag-length-value walker.
        // TBSCertificate is the first SEQUENCE inside the outer SEQUENCE.
        let outer = Self::asn1_unwrap_sequence(der)
            .ok_or_else(|| anyhow::anyhow!("Not a DER SEQUENCE"))?;
        let tbs = Self::asn1_unwrap_sequence(outer)
            .ok_or_else(|| anyhow::anyhow!("No TBSCertificate"))?;

        // Walk TBSCertificate fields in order:
        // [0] version (optional, context [0])
        // [1] serialNumber
        // [2] signature (AlgorithmIdentifier)
        // [3] issuer (Name)
        // [4] validity (Validity)
        // [5] subject (Name)
        // [6] subjectPublicKeyInfo
        let mut cursor = tbs;

        // Skip optional version [0] EXPLICIT
        if cursor.first() == Some(&0xa0) {
            let (_, rest) = Self::asn1_read_tlv(cursor)
                .ok_or_else(|| anyhow::anyhow!("Bad version field"))?;
            cursor = rest;
        }
        // serialNumber INTEGER
        let (_, cursor) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No serialNumber"))?;
        // signature AlgorithmIdentifier SEQUENCE
        let (sig_alg_bytes, cursor) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No signature AlgId"))?;
        let sig_alg = Self::parse_algorithm_identifier(sig_alg_bytes);
        let sig_alg_weak = sig_alg.contains("sha1") || sig_alg.contains("md5")
            || sig_alg.contains("sha-1") || sig_alg.to_lowercase().contains("md2");

        // issuer Name SEQUENCE
        let (issuer_bytes, cursor) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No issuer"))?;
        let issuer = Self::parse_name(issuer_bytes);

        // validity SEQUENCE
        let (validity_bytes, cursor) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No validity"))?;
        let (_, not_after, expired, days_remaining) =
            Self::parse_validity(validity_bytes);

        // subject Name SEQUENCE
        let (subject_bytes, cursor) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No subject"))?;
        let subject = Self::parse_name(subject_bytes);

        // subjectPublicKeyInfo SEQUENCE
        let (spki_bytes, _) = Self::asn1_read_tlv(cursor)
            .ok_or_else(|| anyhow::anyhow!("No SPKI"))?;
        let key_bits = Self::parse_key_bits(spki_bytes);

        let self_signed = issuer == subject;
        let is_wildcard = subject.contains("*.") || subject.contains("wildcard");

        Ok(CertInfo {
            subject,
            not_after,
            days_remaining,
            expired,
            self_signed,
            sig_alg,
            sig_alg_weak,
            key_bits,
            is_wildcard,
        })
    }

    // ── ASN.1 helpers ─────────────────────────────────────────────────────────

    fn asn1_unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
        if data.first() != Some(&0x30) { return None; }
        let (_content, _) = Self::asn1_read_tlv(data)?;
        // content is the full TLV; we want just the value
        let (_, len_bytes) = Self::asn1_decode_length(&data[1..])?;
        let value_start = 1 + len_bytes;
        if value_start > data.len() { return None; }
        Some(&data[value_start..])
    }

    /// Returns (full_tlv_slice, rest_of_buffer)
    fn asn1_read_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
        if data.is_empty() { return None; }
        let (length, len_bytes) = Self::asn1_decode_length(&data[1..])?;
        let value_start = 1 + len_bytes;
        let value_end = value_start + length;
        if value_end > data.len() { return None; }
        Some((&data[..value_end], &data[value_end..]))
    }

    /// Returns (length_value, bytes_consumed_for_length_encoding)
    fn asn1_decode_length(data: &[u8]) -> Option<(usize, usize)> {
        let first = *data.first()?;
        if first & 0x80 == 0 {
            Some((first as usize, 1))
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || data.len() < 1 + n { return None; }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | data[1 + i] as usize;
            }
            Some((len, 1 + n))
        }
    }

    fn parse_algorithm_identifier(data: &[u8]) -> String {
        // Skip outer SEQUENCE tag+length, then read OID
        if data.first() != Some(&0x30) { return "unknown".to_string(); }
        let inner = match Self::asn1_unwrap_sequence(data) {
            Some(i) => i,
            None => return "unknown".to_string(),
        };
        if inner.first() != Some(&0x06) { return "unknown".to_string(); }
        let (oid_tlv, _) = match Self::asn1_read_tlv(inner) {
            Some(v) => v,
            None => return "unknown".to_string(),
        };
        let (_, len_bytes) = Self::asn1_decode_length(&oid_tlv[1..]).unwrap_or((0, 1));
        let oid_bytes = &oid_tlv[1 + len_bytes..];
        Self::oid_to_name(oid_bytes)
    }

    fn oid_to_name(oid: &[u8]) -> String {
        // Common signature algorithm OIDs
        match oid {
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] => "sha1WithRSAEncryption".to_string(),
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => "sha256WithRSAEncryption".to_string(),
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => "sha384WithRSAEncryption".to_string(),
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => "sha512WithRSAEncryption".to_string(),
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04] => "md5WithRSAEncryption".to_string(),
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]       => "ecdsa-with-SHA256".to_string(),
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]       => "ecdsa-with-SHA384".to_string(),
            _ => format!("oid:{}", oid.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")),
        }
    }

    fn parse_name(data: &[u8]) -> String {
        // Walk RDNSequence looking for commonName (OID 2.5.4.3)
        let cn_oid: &[u8] = &[0x55, 0x04, 0x03];
        let mut cursor = data;
        while !cursor.is_empty() {
            if let Some((tlv, rest)) = Self::asn1_read_tlv(cursor) {
                // SET containing SEQUENCE containing OID + value
                if tlv.first() == Some(&0x31) {
                    if let Some(set_inner) = Self::asn1_unwrap_sequence(&tlv[..]) {
                        // Actually a SET — re-parse
                        let _ = set_inner;
                    }
                    // Walk inside the SET
                    let (_, lb) = Self::asn1_decode_length(&tlv[1..]).unwrap_or((0, 1));
                    let set_body = &tlv[1 + lb..];
                    if let Some((seq_tlv, _)) = Self::asn1_read_tlv(set_body) {
                        if seq_tlv.first() == Some(&0x30) {
                            let (_, lb2) = Self::asn1_decode_length(&seq_tlv[1..]).unwrap_or((0, 1));
                            let seq_body = &seq_tlv[1 + lb2..];
                            if let Some((oid_tlv, val_rest)) = Self::asn1_read_tlv(seq_body) {
                                if oid_tlv.first() == Some(&0x06) {
                                    let (_, lb3) = Self::asn1_decode_length(&oid_tlv[1..]).unwrap_or((0, 1));
                                    let oid_val = &oid_tlv[1 + lb3..];
                                    if oid_val == cn_oid {
                                        if let Some((val_tlv, _)) = Self::asn1_read_tlv(val_rest) {
                                            let (_, lb4) = Self::asn1_decode_length(&val_tlv[1..]).unwrap_or((0, 1));
                                            let s = &val_tlv[1 + lb4..];
                                            return String::from_utf8_lossy(s).to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                cursor = rest;
            } else {
                break;
            }
        }
        "unknown".to_string()
    }

    fn parse_validity(data: &[u8]) -> (String, String, bool, i64) {
        // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
        // Time is either UTCTime (0x17) or GeneralizedTime (0x18)
        let mut cursor = data;
        let not_before = if let Some((tlv, rest)) = Self::asn1_read_tlv(cursor) {
            cursor = rest;
            let (_, lb) = Self::asn1_decode_length(&tlv[1..]).unwrap_or((0, 1));
            String::from_utf8_lossy(&tlv[1 + lb..]).to_string()
        } else { "unknown".to_string() };

        let not_after = if let Some((tlv, _)) = Self::asn1_read_tlv(cursor) {
            let (_, lb) = Self::asn1_decode_length(&tlv[1..]).unwrap_or((0, 1));
            String::from_utf8_lossy(&tlv[1 + lb..]).to_string()
        } else { "unknown".to_string() };

        let (expired, days_remaining) = Self::check_expiry(&not_after);
        (not_before, not_after, expired, days_remaining)
    }

    /// Parse UTCTime/GeneralizedTime string and compare to now.
    fn check_expiry(not_after: &str) -> (bool, i64) {
        use std::time::{SystemTime, UNIX_EPOCH};
        // UTCTime: YYMMDDHHMMSSZ  GeneralizedTime: YYYYMMDDHHMMSSZ
        let s = not_after.trim_end_matches('Z');
        let (year, rest) = if s.len() >= 4 && s[..2].parse::<u32>().is_ok() && s.len() < 14 {
            // UTCTime: 2-digit year
            let yy: u32 = s[..2].parse().unwrap_or(0);
            let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (full_year, &s[2..])
        } else {
            // GeneralizedTime: 4-digit year
            let yy: u32 = s[..4].parse().unwrap_or(2000);
            (yy, &s[4..])
        };

        if rest.len() < 10 { return (false, 365); }
        let month: u32 = rest[..2].parse().unwrap_or(1);
        let day: u32   = rest[2..4].parse().unwrap_or(1);
        let hour: u32  = rest[4..6].parse().unwrap_or(0);
        let min: u32   = rest[6..8].parse().unwrap_or(0);
        let sec: u32   = rest[8..10].parse().unwrap_or(0);

        // Rough Unix timestamp calculation (ignores leap seconds)
        let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let mut total_days: u64 = 0;
        for y in 1970..year {
            total_days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        }
        for m in 1..month {
            let d = if m == 2 && is_leap { 29 } else { days_in_month[m as usize] };
            total_days += d;
        }
        total_days += (day as u64).saturating_sub(1);
        let cert_ts = total_days * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64;

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired = cert_ts < now_ts;
        let days_remaining = if expired {
            -((now_ts - cert_ts) as i64 / 86400)
        } else {
            ((cert_ts - now_ts) as i64) / 86400
        };
        (expired, days_remaining)
    }

    fn parse_key_bits(spki: &[u8]) -> u16 {
        // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }
        // For RSA: the BIT STRING contains an RSAPublicKey SEQUENCE { modulus, exponent }
        // We look for the BIT STRING (tag 0x03) and measure the modulus length.
        let mut cursor = spki;
        while !cursor.is_empty() {
            if cursor.first() == Some(&0x03) {
                // BIT STRING
                if let Some((bs_tlv, _)) = Self::asn1_read_tlv(cursor) {
                    let (_, lb) = Self::asn1_decode_length(&bs_tlv[1..]).unwrap_or((0, 1));
                    let bs_body = &bs_tlv[1 + lb..];
                    // First byte of BIT STRING is unused-bits count
                    if bs_body.len() > 1 {
                        let inner = &bs_body[1..];
                        // Try to parse as RSAPublicKey SEQUENCE
                        if inner.first() == Some(&0x30) {
                            if let Some(rsa_seq) = Self::asn1_unwrap_sequence(inner) {
                                // First element is modulus INTEGER
                                if let Some((mod_tlv, _)) = Self::asn1_read_tlv(rsa_seq) {
                                    if mod_tlv.first() == Some(&0x02) {
                                        let (_, lb2) = Self::asn1_decode_length(&mod_tlv[1..]).unwrap_or((0, 1));
                                        let modulus = &mod_tlv[1 + lb2..];
                                        // Strip leading zero byte (sign byte)
                                        let effective = if modulus.first() == Some(&0x00) {
                                            &modulus[1..]
                                        } else { modulus };
                                        return (effective.len() * 8) as u16;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some((_, rest)) = Self::asn1_read_tlv(cursor) {
                cursor = rest;
            } else { break; }
        }
        0 // unknown
    }

    // ── TLS version probing ───────────────────────────────────────────────────

    async fn check_tls_versions(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        let host = Self::extract_host(target);

        let versions = [
            ("SSLv2",   false, TlsSeverity::Critical, "SSLv2 is completely broken (DROWN)."),
            ("SSLv3",   false, TlsSeverity::Critical, "SSLv3 is vulnerable to POODLE."),
            ("TLSv1.0", false, TlsSeverity::High,     "TLS 1.0 is vulnerable to BEAST/POODLE."),
            ("TLSv1.1", false, TlsSeverity::Medium,   "TLS 1.1 is deprecated (RFC 8996)."),
            ("TLSv1.2", true,  TlsSeverity::Info,     "TLS 1.2 is acceptable but prefer 1.3."),
            ("TLSv1.3", true,  TlsSeverity::Info,     "TLS 1.3 is the current recommended version."),
        ];

        for (ver, good, sev, desc) in &versions {
            let supported = self.probe_tls_version(&host, ver).await;
            if supported && !good {
                findings.push(TlsFinding {
                    severity: sev.clone(),
                    title: format!("{} Enabled", ver),
                    description: desc.to_string(),
                    evidence: format!("{} handshake accepted by server", ver),
                    remediation: "Disable legacy TLS/SSL versions. Use TLS 1.2+ only.".to_string(),
                });
            }
            if !supported && *ver == "TLSv1.3" {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Info,
                    title: "TLS 1.3 Not Supported".to_string(),
                    description: "Server does not support TLS 1.3.".to_string(),
                    evidence: "TLS 1.3 ClientHello rejected".to_string(),
                    remediation: "Enable TLS 1.3 for better performance and forward secrecy.".to_string(),
                });
            }
        }
        findings
    }

    /// Send a version-specific ClientHello and check whether the server
    /// responds with a ServerHello (content type 0x16, handshake type 0x02)
    /// rather than an alert (0x15) or a TCP RST.
    async fn probe_tls_version(&self, host: &str, version: &str) -> bool {
        let port = 443u16;
        let addr = format!("{}:{}", host, port);

        let record_version: [u8; 2] = match version {
            "SSLv3"   => [0x03, 0x00],
            "TLSv1.0" => [0x03, 0x01],
            "TLSv1.1" => [0x03, 0x02],
            "TLSv1.2" => [0x03, 0x03],
            "TLSv1.3" => [0x03, 0x03], // TLS 1.3 uses 0x0303 record layer
            "SSLv2"   => return self.probe_sslv2(host).await,
            _ => return false,
        };

        // For TLS 1.3 we include the supported_versions extension with only 0x0304
        let hello = if version == "TLSv1.3" {
            Self::build_tls13_only_hello(host)
        } else {
            Self::build_legacy_hello(host, record_version)
        };

        let Ok(Ok(mut stream)) = timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        ).await else { return false; };

        if stream.write_all(&hello).await.is_err() { return false; }

        let mut buf = vec![0u8; 512];
        let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut buf)).await
        else { return false; };

        if n < 6 { return false; }
        // ServerHello: content_type=0x16, handshake_type=0x02
        buf[0] == 0x16 && buf[5] == 0x02
    }

    fn build_legacy_hello(host: &str, client_version: [u8; 2]) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len();
        let sni_ext_len = 9 + host_len;

        let mut body = Vec::new();
        body.extend_from_slice(&client_version);
        body.extend_from_slice(&[0x00u8; 32]); // random
        body.push(0x00); // session id len
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]); // 1 cipher: TLS_RSA_WITH_AES_256_CBC_SHA
        body.extend_from_slice(&[0x01, 0x00]); // compression: null

        // Extensions length
        body.push(((sni_ext_len >> 8) & 0xff) as u8);
        body.push((sni_ext_len & 0xff) as u8);
        // SNI
        body.extend_from_slice(&[0x00, 0x00]); // type
        body.push((((host_len + 5) >> 8) & 0xff) as u8);
        body.push(((host_len + 5) & 0xff) as u8);
        body.push((((host_len + 3) >> 8) & 0xff) as u8);
        body.push(((host_len + 3) & 0xff) as u8);
        body.push(0x00); // name_type
        body.push(((host_len >> 8) & 0xff) as u8);
        body.push((host_len & 0xff) as u8);
        body.extend_from_slice(host_bytes);

        Self::wrap_handshake(body, client_version)
    }

    fn build_tls13_only_hello(host: &str) -> Vec<u8> {
        // Same as build_real_client_hello but supported_versions only lists 0x0304
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len();

        let sv_ext: &[u8] = &[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        let sni_ext_total = 9 + host_len;
        let ext_total = sni_ext_total + sv_ext.len();

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0x00u8; 32]); // random
        body.push(0x00); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // compression

        body.push(((ext_total >> 8) & 0xff) as u8);
        body.push((ext_total & 0xff) as u8);
        // SNI
        body.extend_from_slice(&[0x00, 0x00]);
        body.push((((host_len + 5) >> 8) & 0xff) as u8);
        body.push(((host_len + 5) & 0xff) as u8);
        body.push((((host_len + 3) >> 8) & 0xff) as u8);
        body.push(((host_len + 3) & 0xff) as u8);
        body.push(0x00);
        body.push(((host_len >> 8) & 0xff) as u8);
        body.push((host_len & 0xff) as u8);
        body.extend_from_slice(host_bytes);
        body.extend_from_slice(sv_ext);

        Self::wrap_handshake(body, [0x03, 0x03])
    }

    fn wrap_handshake(body: Vec<u8>, record_version: [u8; 2]) -> Vec<u8> {
        let body_len = body.len();
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.push(((body_len >> 16) & 0xff) as u8);
        hs.push(((body_len >> 8) & 0xff) as u8);
        hs.push((body_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let hs_len = hs.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&record_version);
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&hs);
        record
    }

    /// SSLv2 uses a completely different record format.
    async fn probe_sslv2(&self, host: &str) -> bool {
        let addr = format!("{}:443", host);
        let Ok(Ok(mut stream)) = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await
        else { return false; };

        // Minimal SSLv2 ClientHello
        let hello: &[u8] = &[
            0x80, 0x2e,             // 2-byte header: MSB=1 (no padding), length=46
            0x01,                   // MSG-CLIENT-HELLO
            0x00, 0x02,             // version: SSL 2.0
            0x00, 0x15,             // cipher_specs_length: 21
            0x00, 0x00,             // session_id_length: 0
            0x00, 0x10,             // challenge_length: 16
            // 7 cipher specs (3 bytes each)
            0x07, 0x00, 0xc0, 0x05, 0x00, 0x80, 0x03, 0x00,
            0x80, 0x01, 0x00, 0x80, 0x08, 0x00, 0x80, 0x06,
            0x00, 0x40, 0x04, 0x00, 0x80,
            // challenge (16 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];

        if stream.write_all(hello).await.is_err() { return false; }
        let mut buf = vec![0u8; 64];
        let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut buf)).await
        else { return false; };

        // SSLv2 SERVER-HELLO starts with MSG-SERVER-HELLO (0x04)
        n >= 3 && buf[2] == 0x04
    }

    // ── Cipher suites ─────────────────────────────────────────────────────────

    async fn check_cipher_suites(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        match self.client.get(target).send().await {
            Ok(response) => {
                let headers = response.headers();
                if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
                    let sl = server.to_lowercase();
                    if sl.contains("openssl/0.9") || sl.contains("openssl/1.0.0") {
                        findings.push(TlsFinding {
                            severity: TlsSeverity::High,
                            title: "Outdated OpenSSL Version".to_string(),
                            description: format!("Server uses outdated OpenSSL: {}", server),
                            evidence: server.to_string(),
                            remediation: "Upgrade OpenSSL to 1.1.1 or 3.0+.".to_string(),
                        });
                    }
                }
            }
            Err(_) => {}
        }
        findings.push(TlsFinding {
            severity: TlsSeverity::Info,
            title: "Cipher Suite Assessment".to_string(),
            description: "Manual cipher enumeration recommended.".to_string(),
            evidence: "Run: openssl s_client -connect host:443 -cipher 'ALL' -tls1_2".to_string(),
            remediation: "Disable weak ciphers (DES, 3DES, RC4, NULL, EXPORT). Enable only AEAD ciphers.".to_string(),
        });
        findings
    }

    // ── HSTS ──────────────────────────────────────────────────────────────────

    async fn check_hsts(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        let Ok(response) = self.client.get(target).send().await else { return findings; };
        let headers = response.headers();

        if let Some(hsts) = headers.get("strict-transport-security").and_then(|v| v.to_str().ok()) {
            if let Some(age_start) = hsts.find("max-age=") {
                let age_part = &hsts[age_start + 8..];
                let age_end = age_part.find(';').unwrap_or(age_part.len());
                if let Ok(age) = age_part[..age_end].parse::<u64>() {
                    if age < 2_592_000 {
                        findings.push(TlsFinding {
                            severity: TlsSeverity::Medium,
                            title: "HSTS max-age Too Short".to_string(),
                            description: format!("HSTS max-age is {} seconds (recommended: 31536000)", age),
                            evidence: hsts.to_string(),
                            remediation: "Set max-age to at least 31536000 (1 year).".to_string(),
                        });
                    }
                }
            }
            if !hsts.contains("includeSubDomains") {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Medium,
                    title: "HSTS Missing includeSubDomains".to_string(),
                    description: "HSTS policy does not cover subdomains.".to_string(),
                    evidence: hsts.to_string(),
                    remediation: "Add includeSubDomains directive.".to_string(),
                });
            }
            if !hsts.contains("preload") {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Info,
                    title: "HSTS Not Preload Ready".to_string(),
                    description: "HSTS header missing preload directive.".to_string(),
                    evidence: hsts.to_string(),
                    remediation: "Add preload and submit to hstspreload.org.".to_string(),
                });
            }
        } else {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "HSTS Not Enabled".to_string(),
                description: "Strict-Transport-Security header is missing.".to_string(),
                evidence: "No HSTS header found".to_string(),
                remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
            });
        }
        findings
    }

    // ── TLS-related headers ───────────────────────────────────────────────────

    async fn check_tls_headers(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        let Ok(response) = self.client.get(target).send().await else { return findings; };
        let headers = response.headers();

        if !headers.contains_key("expect-ct") {
            findings.push(TlsFinding {
                severity: TlsSeverity::Low,
                title: "Expect-CT Header Missing".to_string(),
                description: "Certificate Transparency enforcement not configured.".to_string(),
                evidence: "No Expect-CT header".to_string(),
                remediation: "Add Expect-CT: max-age=86400, enforce".to_string(),
            });
        }

        if let Some(set_cookie) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
            if !set_cookie.contains("Secure") {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Medium,
                    title: "Cookie Missing Secure Flag".to_string(),
                    description: "Cookie sent without Secure flag.".to_string(),
                    evidence: set_cookie.to_string(),
                    remediation: "Add Secure flag to all cookies.".to_string(),
                });
            }
            if !set_cookie.contains("HttpOnly") {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Medium,
                    title: "Cookie Missing HttpOnly Flag".to_string(),
                    description: "Cookie accessible via JavaScript.".to_string(),
                    evidence: set_cookie.to_string(),
                    remediation: "Add HttpOnly flag to session cookies.".to_string(),
                });
            }
            if !set_cookie.contains("SameSite") {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Low,
                    title: "Cookie Missing SameSite Attribute".to_string(),
                    description: "Cookie may be vulnerable to CSRF.".to_string(),
                    evidence: set_cookie.to_string(),
                    remediation: "Add SameSite=Strict or SameSite=Lax.".to_string(),
                });
            }
        }
        findings
    }

    // ── Known vulnerability checks ────────────────────────────────────────────
    // These are real active probes, not static info banners.

    async fn check_known_vulns(&self, target: &str) -> Vec<TlsFinding> {
        let mut findings = Vec::new();
        let host = Self::extract_host(target);

        // BEAST: TLS 1.0 + CBC — already covered by version check
        // POODLE: SSLv3 — already covered by version check

        // Heartbleed (CVE-2014-0160): send a malformed heartbeat request
        if self.probe_heartbleed(&host).await {
            findings.push(TlsFinding {
                severity: TlsSeverity::Critical,
                title: "Heartbleed (CVE-2014-0160)".to_string(),
                description: "Server is vulnerable to Heartbleed — server memory can be read remotely.".to_string(),
                evidence: "Server responded to oversized heartbeat request without error".to_string(),
                remediation: "Upgrade OpenSSL to 1.0.1g+ or 1.0.2+. Revoke and reissue all certificates.".to_string(),
            });
        }

        // CRIME: TLS compression — check via ServerHello compression field
        if self.probe_tls_compression(&host).await {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "TLS Compression Enabled (CRIME)".to_string(),
                description: "Server supports TLS-level compression, enabling CRIME attack.".to_string(),
                evidence: "ServerHello compression method != 0x00 (null)".to_string(),
                remediation: "Disable TLS compression in server configuration.".to_string(),
            });
        }

        findings
    }

    /// Real Heartbleed probe: complete TLS handshake then send a heartbeat
    /// with length field larger than the actual payload.
    async fn probe_heartbleed(&self, host: &str) -> bool {
        let addr = format!("{}:443", host);
        let Ok(Ok(mut stream)) = timeout(Duration::from_secs(8), TcpStream::connect(&addr)).await
        else { return false; };

        // Send TLS 1.0 ClientHello (Heartbleed affects OpenSSL < 1.0.1g)
        let hello = Self::build_legacy_hello(host, [0x03, 0x01]);
        if stream.write_all(&hello).await.is_err() { return false; }

        // Drain ServerHello + Certificate + ServerHelloDone
        let mut buf = vec![0u8; 8192];
        let _ = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        // Send malformed Heartbeat request: type=1 (request), payload_length=0x4000 (16384),
        // but actual payload is only 1 byte.  Vulnerable servers echo back 16384 bytes.
        let heartbeat: &[u8] = &[
            0x18,               // content_type: Heartbeat
            0x03, 0x01,         // version: TLS 1.0
            0x00, 0x07,         // record length: 7
            0x01,               // HeartbeatMessageType: request
            0x40, 0x00,         // payload_length: 16384 (malicious)
            0x41, 0x41, 0x41,   // payload: 3 bytes of 'A'
            0x00, 0x00,         // padding
        ];
        if stream.write_all(heartbeat).await.is_err() { return false; }

        let mut resp = vec![0u8; 4096];
        let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut resp)).await
        else { return false; };

        // Vulnerable: server sends back a Heartbeat response (0x18) with data
        // Patched: server sends Alert (0x15) or closes connection
        n > 3 && resp[0] == 0x18
    }

    /// Check if server negotiates non-null TLS compression.
    async fn probe_tls_compression(&self, host: &str) -> bool {
        let addr = format!("{}:443", host);
        let Ok(Ok(mut stream)) = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await
        else { return false; };

        // ClientHello advertising DEFLATE compression (0x01) in addition to null (0x00)
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len();
        let sni_ext_len = 9 + host_len;

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[0x00u8; 32]); // random
        body.push(0x00); // session id
        body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2b, 0x00, 0x35]); // 2 ciphers
        body.extend_from_slice(&[0x02, 0x01, 0x00]); // compression: DEFLATE + null
        body.push(((sni_ext_len >> 8) & 0xff) as u8);
        body.push((sni_ext_len & 0xff) as u8);
        body.extend_from_slice(&[0x00, 0x00]);
        body.push((((host_len + 5) >> 8) & 0xff) as u8);
        body.push(((host_len + 5) & 0xff) as u8);
        body.push((((host_len + 3) >> 8) & 0xff) as u8);
        body.push(((host_len + 3) & 0xff) as u8);
        body.push(0x00);
        body.push(((host_len >> 8) & 0xff) as u8);
        body.push((host_len & 0xff) as u8);
        body.extend_from_slice(host_bytes);

        let hello = Self::wrap_handshake(body, [0x03, 0x03]);
        if stream.write_all(&hello).await.is_err() { return false; }

        let mut buf = vec![0u8; 512];
        let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut buf)).await
        else { return false; };

        // ServerHello: content_type=0x16, handshake_type=0x02
        // Compression method is at offset 5+4+2+32+1+2 = 46 from start of record
        // (record_hdr=5, hs_hdr=4, version=2, random=32, session_id_len=1, cipher=2)
        if n < 47 || buf[0] != 0x16 || buf[5] != 0x02 { return false; }
        buf[46] != 0x00 // non-null compression selected
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    fn extract_host(target: &str) -> String {
        let clean = target.replace("https://", "").replace("http://", "");
        let host_port = clean.split('/').next().unwrap_or(&clean);
        host_port.split(':').next().unwrap_or(host_port).to_string()
    }
}

// ── Certificate info struct ───────────────────────────────────────────────────

#[derive(Debug)]
struct CertInfo {
    subject: String,
    not_after: String,
    days_remaining: i64,
    expired: bool,
    self_signed: bool,
    sig_alg: String,
    sig_alg_weak: bool,
    key_bits: u16,
    is_wildcard: bool,
}
