pub struct Mutator;

impl Mutator {
    pub fn new() -> Self {
        Self
    }

    pub fn mutate_path(&self, path: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(path.to_string());
        mutations.push(path.to_uppercase());
        mutations.push(path.to_lowercase());
        mutations.push(path.replace("/", "%2f"));
        mutations.push(path.replace("/", "%252f"));
        mutations.push(format!("{}/", path));
        mutations.push(format!("{}/.", path));
        mutations.push(format!("{}/..", path));
        mutations.push(format!("{}/../", path));
        mutations.push(format!("{}/%2e%2e/", path));
        
        mutations
    }

    pub fn mutate_param(&self, param: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(param.to_string());
        
        if param.contains('=') {
            let parts: Vec<&str> = param.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];
                
                mutations.push(format!("{}={}", key, urlencoding::encode(value)));
                mutations.push(format!("{}={}", key, Self::double_encode(value)));
                mutations.push(format!("{}={}%00", key, value));
                mutations.push(format!("{}={}%0d%0a", key, value));
                mutations.push(format!("{}[]={}", key, value));
                mutations.push(format!("{}[0]={}", key, value));
                mutations.push(format!("{}=<script>alert(1)</script>", key));
                mutations.push(format!("{}=' OR '1'='1", key));
                mutations.push(format!("{}=1 AND 1=1", key));
                mutations.push(format!("{}=../../../../etc/passwd", key));
            }
        }
        
        mutations
    }

    pub fn mutate_header(&self, header: &str) -> Vec<String> {
        let mut mutations = vec![];
        
        mutations.push(header.to_string());
        
        if header.contains(':') {
            let parts: Vec<&str> = header.splitn(2, ':').collect();
            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1].trim();
                
                mutations.push(format!("{}: {}", key, value));
                mutations.push(format!("{}: {}", key, value.replace(".", "[.]")));
                mutations.push(format!("{}: {}.local", key, value));
                mutations.push(format!("{}: {}:80", key, value));
                mutations.push(format!("{}: {}:443", key, value));
                mutations.push(format!("{}: null.{}", key, value));
                mutations.push(format!("{}: {}%0d%0a", key, value));
            }
        }
        
        mutations
    }

    fn double_encode(input: &str) -> String {
        urlencoding::encode(&urlencoding::encode(input)).to_string()
    }
}

impl Clone for Mutator {
    fn clone(&self) -> Self {
        Self
    }
}
