use crate::crypto::{self, CryptoError};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("authentication failed")]
    Auth,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    verifier: String,
    secrets: BTreeMap<String, String>,
}

pub struct Vault {
    password: String,
    secrets: BTreeMap<String, String>,
}

impl Vault {
    pub fn create(password: &str) -> Result<Self, VaultError> {
        Ok(Self {
            password: password.to_string(),
            secrets: BTreeMap::new(),
        })
    }

    pub fn load(path: &Path, password: &str) -> Result<Self, VaultError> {
        let raw = std::fs::read_to_string(path)?;
        let file: VaultFile = serde_json::from_str(&raw)?;
        let verifier = hex::decode(&file.verifier).map_err(|_| VaultError::Auth)?;
        let check = crypto::decrypt(password, &verifier).map_err(|_| VaultError::Auth)?;
        if check != b"vault-ok" {
            return Err(VaultError::Auth);
        }

        let mut secrets = BTreeMap::new();
        for (name, enc_hex) in file.secrets {
            let blob = hex::decode(&enc_hex).map_err(|_| VaultError::Auth)?;
            let value = crypto::decrypt(password, &blob)?;
            let value = String::from_utf8(value).map_err(|_| VaultError::Auth)?;
            secrets.insert(name, value);
        }

        Ok(Self {
            password: password.to_string(),
            secrets,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let verifier = crypto::encrypt(&self.password, b"vault-ok")?;
        let mut secrets = BTreeMap::new();
        for (name, value) in &self.secrets {
            let blob = crypto::encrypt(&self.password, value.as_bytes())?;
            secrets.insert(name.clone(), hex::encode(blob));
        }
        let file = VaultFile {
            verifier: hex::encode(verifier),
            secrets,
        };
        let json = serde_json::to_string_pretty(&file)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<(), VaultError> {
        self.secrets.insert(name.to_string(), value.to_string());
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Option<String>, VaultError> {
        Ok(self.secrets.get(name).cloned())
    }

    pub fn delete(&mut self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    pub fn list(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn set_get_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut v = Vault::create("pw").unwrap();
        v.set("API_KEY", "abc123").unwrap();
        v.save(&path).unwrap();

        let loaded = Vault::load(&path, "pw").unwrap();
        assert_eq!(loaded.get("API_KEY").unwrap().unwrap(), "abc123");
        assert_eq!(loaded.list(), vec!["API_KEY".to_string()]);
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let v = Vault::create("pw").unwrap();
        v.save(&path).unwrap();
        assert!(Vault::load(&path, "nope").is_err());
    }
}
