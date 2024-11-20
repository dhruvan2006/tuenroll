use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use crate::api;

/// Represents user credentials, including username, password, and access token.
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Credentials {
    username: Option<String>,
    password: Option<String>,
    pub access_token: Option<String>,
}

impl Credentials {
    /// Serializes and saves the current credentials to the specified config file.
    ///
    /// Creates the parent directory if it doesn't exist and writes the credentials as JSON to
    /// the file. Returns an error if serialization or file operations fail.
    fn save(&self, config_path: &Path) -> Result<(), Box<dyn Error>> {
        let serialized = serde_json::to_string(self)?;

        // Ensure the parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        } else {
            return Err("Failed to get parent directory".into());
        }

        fs::write(config_path, serialized)?;

        Ok(())
    }

    /// Load credentials from a file, returning `None` if the file is missing or invalid.
    fn load(config_path: &Path) -> Option<Self> {
        match fs::read_to_string(config_path) {
            Ok(data) => serde_json::from_str(&data).ok(),
            Err(_) => None,
        }
    }

    /// Checks if all fields in the credentials are empty (i.e., None).
    fn is_empty(&self) -> bool {
        self.username.is_none() && self.password.is_none() && self.access_token.is_none()
    }
}

pub struct CredentialManager {
    config_path: PathBuf,
}

impl CredentialManager {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    pub fn delete_credentials(&self) {
        let creds = Credentials::default();
        let _ = creds.save(&self.config_path);
    }

    /// Prompt the user for credentials.
    // TODO: Test
    fn prompt_for_credentials(&self) -> Credentials {
        let mut username = String::new();

        print!("Username: ");
        let _ = io::stdout().flush();
        io::stdin()
            .read_line(&mut username)
            .expect("Couldn't read username");

        print!("Password: ");
        let _ = io::stdout().flush();
        let password = rpassword::read_password().expect("Failed to read password");

        Credentials {
            username: Some(username.trim().to_string()),
            password: Some(password.trim().to_string()),
            access_token: None,
        }
    }

    // TODO: Test
    pub async fn change_credentials(&self) -> Result<Credentials, Box<dyn Error>> {
        self.delete_credentials();
        self.get_valid_credentials().await
    }

    /// Retrieves valid credentials with an access token.
    /// If the access token is missing or invalid, it fetches a new one and updates the config.
    // TODO: Test
    pub async fn get_valid_credentials(&self) -> Result<Credentials, Box<dyn Error>> {
        let mut credentials = Credentials::load(&self.config_path).unwrap_or_default();

        loop {
            if credentials.is_empty() {
                credentials = self.prompt_for_credentials();
            }

            let pb = self.setup_progress_bar(&mut credentials);
            if self
                .validate_stored_token(&mut credentials, api::REGISTERED_COURSE_URL)
                .await?
            {
                self.cleanup_progress_bar(&pb);
                return Ok(credentials);
            }

            if let Err(e) = self.retrieve_new_access_token(&mut credentials).await {
                self.cleanup_progress_bar(&pb);
                eprintln!("{}", format!("Login failed: {e}.").red().bold());
            } else {
                self.cleanup_progress_bar(&pb);
                println!("{}", "Credentials validated successfully!".green().bold());
                return Ok(credentials);
            }

            self.cleanup_progress_bar(&pb);
            credentials = self.prompt_for_credentials();
        }
    }

    async fn validate_stored_token(
        &self,
        credentials: &mut Credentials,
        url: &str,
    ) -> Result<bool, Box<dyn Error>> {
        if let Some(token) = &credentials.access_token {
            let is_valid = api::is_user_authenticated(token, url)
                .await
                .unwrap_or(false);
            return Ok(is_valid);
        }
        Ok(false)
    }

    async fn retrieve_new_access_token(
        &self,
        credentials: &mut Credentials,
    ) -> Result<(), Box<dyn Error>> {
        // Request new access_token
        if let (Some(username), Some(password)) = (&credentials.username, &credentials.password) {
            let result = api::get_access_token(username, password).await;
            return if let Ok(token) = result {
                credentials.access_token = Some(token);
                let _ = credentials.save(&self.config_path);
                Ok(())
            } else {
                match result {
                    Err(e) if e.to_string().contains("error sending request") => {
                        Err("Network request error".into())
                    }
                    _ => Err("Invalid credentials".into()),
                }
            };
        }
        Err("A network error likely occurred".into())
    }

    /// Setup progress bar for long operations.
    fn setup_progress_bar(&self, credentials: &mut Credentials) -> Option<ProgressBar> {
        if env::var("DAEMONIZED").is_ok() || credentials.is_empty() {
            return None;
        }

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb.set_message("Validating credentials...");
        Some(pb)
    }

    /// Cleanup progress bar.
    fn cleanup_progress_bar(&self, pb: &Option<ProgressBar>) {
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::CONFIG_FILE;

    use super::*;
    use fs::{metadata, File};
    use tempfile::tempdir;

    #[test]
    fn test_save_credentials_success() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        };

        let result = credentials.save(&config_path);
        assert!(result.is_ok());

        // Check if the file exists
        assert!(metadata(&config_path).is_ok());

        // Check if saved file includes the credentials
        let saved = fs::read_to_string(config_path).expect("Failed to read config file");
        assert!(saved.contains("test_user"));
        assert!(saved.contains("test_password"));
        assert!(saved.contains("test_token"));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_save_credentials_invalid_path() {
        let invalid_path = Path::new("/invalid/directory/path/test_config.json");

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        };

        let result = credentials.save(&invalid_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_empty_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let empty_credentials = Credentials::default();

        let result = empty_credentials.save(&config_path);
        assert!(result.is_ok());

        // Check if the file exists
        assert!(metadata(&config_path).is_ok());

        // Check if saved file includes the credentials
        let saved = fs::read_to_string(config_path).expect("Failed to read config file");
        assert!(saved.contains("null"));
    }

    #[test]
    fn test_load_credentials_success() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        };

        // Serialize the credentials and write them to the file
        let serialized =
            serde_json::to_string(&credentials).expect("Failed to serialize credentials");
        let mut file = File::create(&config_path).expect("Failed to create file");
        file.write_all(serialized.as_bytes())
            .expect("Failed to write to file");

        let loaded_credentials = Credentials::load(&config_path);

        assert!(loaded_credentials.is_some());
        let loaded_credentials = loaded_credentials.unwrap();
        assert_eq!(loaded_credentials.username, credentials.username);
        assert_eq!(loaded_credentials.password, credentials.password);
        assert_eq!(loaded_credentials.access_token, credentials.access_token);
    }

    #[test]
    fn test_load_credentials_missing_file() {
        let invalid_path = Path::new("non_existent_config.json");

        let loaded_credentials = Credentials::load(invalid_path);

        // Assert that loading fails (returns None)
        assert!(loaded_credentials.is_none());
    }

    #[test]
    fn test_is_empty_all_none() {
        let credentials = Credentials::default();

        assert!(credentials.is_empty());
    }

    #[test]
    fn test_is_empty_some_fields() {
        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        assert!(!credentials.is_empty());
    }

    #[test]
    fn test_is_empty_all_some() {
        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        };

        assert!(!credentials.is_empty());
    }

    #[test]
    fn test_delete_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        };

        let _ = credentials.save(&config_path);

        let manager = CredentialManager::new(config_path.clone());
        manager.delete_credentials();

        let loaded_credentials = Credentials::load(&config_path);
        assert!(loaded_credentials.is_some());

        // Check if all fields are `None`
        let loaded_credentials = loaded_credentials.unwrap();
        assert!(loaded_credentials.is_empty());
    }

    // TODO: Use mocked API
    // #[tokio::test]
    // async fn test_validate_stored_token_with_valid_token() {
    //     let mut server = mockito::Server::new_async().await;
    //     let _mock = server
    //         .mock("GET", "/test")
    //         .with_status(200)
    //         .with_header("Authorization", "Bearer valid_token")
    //         .with_body(
    //             serde_json::json!({
    //                 "random": "json test body"
    //             })
    //             .to_string(),
    //         )
    //         .create();
    //
    //     let mut credentials = Credentials {
    //         username: Some("test_user".to_string()),
    //         password: Some("test_password".to_string()),
    //         access_token: Some("valid_token".to_string()),
    //     };
    //
    //     let manager =
    //         CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));
    //
    //     let url = format!("{}/test", server.url());
    //     let result = manager.validate_stored_token(&mut credentials, &url).await;
    //     assert!(result.unwrap());
    // }

    #[tokio::test]
    async fn test_validate_stored_token_with_expired_token() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header("Authorization", "Bearer valid_token")
            .with_body("")
            .create();

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("expired_token".to_string()),
        };

        let manager =
            CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

        let url = format!("{}/test", server.url());
        let result = manager.validate_stored_token(&mut credentials, &url).await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_stored_token_with_none_token() {
        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let manager =
            CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));
        let result = manager.validate_stored_token(&mut credentials, "").await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_invalid_url() {
        let mut credentials = Credentials {
            username: Some("valid_user".to_string()),
            password: Some("valid_pass".to_string()),
            ..Default::default()
        };

        let manager =
            CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_invalid_password() {
        let mut credentials = Credentials {
            username: Some("valid_user".to_string()),
            password: Some("incorrect".to_string()),
            ..Default::default()
        };

        let manager =
            CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        assert!(credentials.access_token.is_none());
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_missing_creds() {
        let mut credentials = Credentials::default();

        let manager =
            CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        assert!(credentials.is_empty());
    }
}
