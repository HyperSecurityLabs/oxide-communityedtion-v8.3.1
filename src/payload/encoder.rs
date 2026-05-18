// ── Encoder — HyperSecurity_Offensive_Labs / khaninkali ──────────────────────
// Payload encoding and obfuscation engine designed to evade WAF/IPS/IDS
// signatures during offensive operations. Supports layered encoding for
// deep inspection bypass, mixed-case transformations, comment injection,
// and encoding combinations that real red teams use in the field.

pub struct Encoder;

impl Encoder {
    pub fn url_encode(input: &str) -> String {
        urlencoding::encode(input).to_string()
    }

    pub fn base64_encode(input: &str) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(input.as_bytes())
    }

    pub fn hex_encode(input: &str) -> String {
        hex::encode(input.as_bytes())
    }

    pub fn double_encode(input: &str) -> String {
        Self::url_encode(&Self::url_encode(input))
    }
}
