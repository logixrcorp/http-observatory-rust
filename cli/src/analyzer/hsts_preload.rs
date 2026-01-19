use std::collections::HashMap;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use anyhow::Result;

#[derive(Deserialize)]
struct ChromiumEntry {
    name: String,
    include_subdomains: Option<bool>,
    #[allow(dead_code)]
    mode: Option<String>,
}

#[derive(Deserialize)]
struct ChromiumPreload {
    entries: Vec<ChromiumEntry>,
}

pub struct HstsPreload {
    domains: HashMap<String, bool>, // Map domain -> include_subdomains
}

impl HstsPreload {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    pub fn load_from_file(&mut self, path: &str) -> Result<()> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Chromium JSON has comments "//". We need to strip them.
        let json_str: String = contents
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();

        let preload: ChromiumPreload = serde_json::from_str(&json_str)?;

        for entry in preload.entries {
            self.domains.insert(entry.name, entry.include_subdomains.unwrap_or(false));
        }

        Ok(())
    }

    pub fn is_preloaded(&self, domain: &str) -> bool {
        self.domains.contains_key(domain)
    }
}
