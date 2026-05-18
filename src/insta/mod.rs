use anyhow::{Context, Result};
use std::path::PathBuf;

const INSTAGRAM_BASE: &str = "https://www.instagram.com";

#[derive(Debug, Clone)]
pub struct InstaProfile {
    pub username: String,
    pub full_name: String,
    pub bio: String,
    pub follower_count: u64,
    pub following_count: u64,
    pub post_count: u64,
    pub is_private: bool,
    pub is_verified: bool,
    pub profile_pic_url: String,
    pub tracking_id: String,
}

#[derive(Debug, Clone)]
pub struct InstaOSINT {
    client: reqwest::Client,
}

impl InstaOSINT {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self { client })
    }

    fn extract_username(target: &str) -> String {
        let cleaned = target.trim().trim_end_matches('/');
        if cleaned.contains("instagram.com") {
            cleaned.rsplit('/').next().unwrap_or(cleaned).to_string()
        } else {
            cleaned.to_string()
        }
    }

    fn extract_tracking_id(target: &str) -> String {
        if let Some(pos) = target.find("id=") {
            let rest = &target[pos + 3..];
            rest.split('&').next().unwrap_or("233").to_string()
        } else {
            "233".to_string()
        }
    }

    pub async fn scan_profile(&self, target: &str) -> Result<InstaProfile> {
        let username = Self::extract_username(target);
        let tracking_id = Self::extract_tracking_id(target);
        let profile_url = format!("{}/{}/", INSTAGRAM_BASE, username);

        let resp = self.client.get(&profile_url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.5")
            .send()
            .await
            .context("Failed to fetch Instagram profile")?;

        let body = resp.text().await.context("Failed to read response body")?;

        let full_name = Self::extract_meta(&body, "og:title")
            .unwrap_or_else(|| username.clone());
        let bio = Self::extract_meta(&body, "description")
            .unwrap_or_default();
        let profile_pic_url = Self::extract_meta(&body, "og:image")
            .unwrap_or_default();

        let follower_count = Self::parse_count(&body, "edge_followed_by")
            .or_else(|| Self::parse_count_from_text(&body, "followers"))
            .unwrap_or(0);
        let following_count = Self::parse_count(&body, "edge_follow")
            .or_else(|| Self::parse_count_from_text(&body, "following"))
            .unwrap_or(0);
        let post_count = Self::parse_count(&body, "edge_owner_to_timeline_media")
            .or_else(|| Self::parse_count_from_text(&body, "posts"))
            .unwrap_or(0);

        let is_private = body.contains("\"is_private\": true")
            || body.contains("This Account is Private");
        let is_verified = body.contains("\"is_verified\": true");

        Ok(InstaProfile {
            username,
            full_name,
            bio,
            follower_count,
            following_count,
            post_count,
            is_private,
            is_verified,
            profile_pic_url,
            tracking_id,
        })
    }

    pub async fn follower_count(&self, target: &str) -> Result<u64> {
        let profile = self.scan_profile(target).await?;
        Ok(profile.follower_count)
    }

    pub async fn is_private(&self, target: &str) -> Result<bool> {
        let profile = self.scan_profile(target).await?;
        Ok(profile.is_private)
    }

    pub async fn download_profile_pic(&self, target: &str, output_dir: &str) -> Result<PathBuf> {
        let profile = self.scan_profile(target).await?;
        let dir = PathBuf::from(output_dir);
        std::fs::create_dir_all(&dir).context("Failed to create output directory")?;

        let ext = if profile.profile_pic_url.contains(".jpg") { "jpg" }
                  else if profile.profile_pic_url.contains(".png") { "png" }
                  else { "jpg" };
        let filename = format!("{}_{}.{}", profile.username, profile.tracking_id, ext);
        let path = dir.join(&filename);

        let img_bytes = self.client.get(&profile.profile_pic_url)
            .send().await
            .context("Failed to download profile picture")?
            .bytes().await
            .context("Failed to read image data")?;

        std::fs::write(&path, &img_bytes)
            .context("Failed to save profile picture")?;
        Ok(path)
    }

    pub async fn full_scan(&self, target: &str) -> Result<Vec<crate::detection::analyzer::Finding>> {
        let profile = self.scan_profile(target).await?;
        let mut findings = Vec::new();

        use crate::detection::analyzer::{Finding, Severity};

        findings.push(Finding::new(target, Severity::Info, "Instagram Profile OSINT", &format!(
            "User: @{} | Name: {} | Bio: {} | Posts: {} | Followers: {} | Following: {}",
            profile.username, profile.full_name, profile.bio, profile.post_count,
            profile.follower_count, profile.following_count,
        )).with_evidence(&format!(
            "Profile: https://www.instagram.com/{}/\nTracking ID: {}\nPrivate: {}",
            profile.username, profile.tracking_id, profile.is_private,
        )));

        if profile.is_private {
            findings.push(Finding::new(target, Severity::Medium,
                "Private Instagram Profile Detected",
                "The target account is private — limited OSINT data available"
            ).with_evidence(&format!("Account @{} requires follow request to view posts", profile.username))
             .with_remediation("Target may be security-conscious; respect privacy settings"));
        }

        if profile.is_verified {
            findings.push(Finding::new(target, Severity::Info,
                "Verified Instagram Account",
                "Target account has Instagram verification badge"
            ).with_evidence(&format!("@{} is verified on Instagram", profile.username)));
        }

        findings.push(Finding::new(target, Severity::Info,
            "Instagram Tracking Parameter",
            &format!("Target URL contains id={} tracking parameter", profile.tracking_id)
        ).with_evidence(&format!("Tracking ID: {} | Used for user/request correlation", profile.tracking_id)));

        Ok(findings)
    }

    fn extract_meta(body: &str, property: &str) -> Option<String> {
        let patterns = [
            format!("<meta property=\"{}\" content=\"", property),
            format!("<meta name=\"{}\" content=\"", property),
        ];
        for pat in &patterns {
            if let Some(start) = body.find(pat.as_str()) {
                let start = start + pat.len();
                if let Some(end) = body[start..].find('\"') {
                    let value = &body[start..start + end];
                    if !value.is_empty() {
                        return Some(html_unescape(value));
                    }
                }
            }
        }
        None
    }

    fn parse_count(body: &str, key: &str) -> Option<u64> {
        let patterns = [
            format!("\"{}\":{{\"count\":", key),
            format!("\"{}\": {{\"count\":", key),
        ];
        for pat in &patterns {
            if let Some(start) = body.find(pat.as_str()) {
                let start = start + pat.len();
                let num_str: String = body[start..].chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(n) = num_str.parse::<u64>() {
                    return Some(n);
                }
            }
        }
        None
    }

    fn parse_count_from_text(body: &str, label: &str) -> Option<u64> {
        let patterns = [
            format!(r#"{}<span class="html-span xdj266r x11i5rnm xat24cr x1mh8g0r xexx8yu x4uap5 x18d9i69 xkhd6sd x1hl2dhg x16tdsg8 x1vvkbs">"#, label),
            format!("{} \"count\": ", label),
        ];
        for pat in &patterns {
            if let Some(start) = body.find(pat.as_str()) {
                let num_str: String = body[start..].chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(n) = num_str.parse::<u64>() {
                    return Some(n);
                }
            }
        }
        None
    }
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
     .replace("&lt;", "<")
     .replace("&gt;", ">")
     .replace("&quot;", "\"")
     .replace("&#39;", "'")
     .replace("&#x27;", "'")
}
