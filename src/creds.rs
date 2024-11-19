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
    pub fn prompt_for_credentials(&self) -> Credentials {
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

    pub async fn change_credentials(&self) -> Result<Credentials, Box<dyn Error>> {
        self.delete_credentials();
        self.get_valid_credentials().await
    }

    /// Retrieves valid credentials with an access token.
    /// If the access token is missing or invalid, it fetches a new one and updates the config.
    pub async fn get_valid_credentials(&self) -> Result<Credentials, Box<dyn Error>> {
        let mut credentials = Credentials::load(&self.config_path).unwrap_or_default();
        
        loop {
            let mut pb;
            
            if credentials.is_empty() {
                pb = self.setup_progress_bar(&mut credentials);
                credentials = self.prompt_for_credentials();
                self.cleanup_progress_bar(&pb);
            }

            if self.validate_stored_token(&mut credentials).await? {
                pb = self.setup_progress_bar(&mut credentials);
                self.cleanup_progress_bar(&pb);
                return Ok(credentials);
            }

            pb = self.setup_progress_bar(&mut credentials);
            if let Err(e) = self.validate_and_update_credentials(&mut credentials).await {
                self.cleanup_progress_bar(&pb);
                eprintln!("{}", format!("Login failed: {e}.").red().bold());
            } else {
                self.cleanup_progress_bar(&pb);
                return Ok(credentials);
            }

            self.cleanup_progress_bar(&pb);
            credentials = self.prompt_for_credentials();
        }
    }

    async fn validate_stored_token(&self, credentials: &mut Credentials) -> Result<bool, Box<dyn Error>> {
        if let Some(token) = &credentials.access_token {
            let is_valid = api::is_user_authenticated(token, api::REGISTERED_COURSE_URL)
                .await
                .unwrap_or(false);
            return Ok(is_valid);
        }
        Ok(false)
    }

    async fn validate_and_update_credentials(&self, credentials: &mut Credentials) -> Result<(), Box<dyn Error>> {
        // Validate credentials or request new ones
        if let (Some(username), Some(password)) = (&credentials.username, &credentials.password)
        {
            if let Ok(new_token) = api::get_access_token(username, password).await {
                credentials.access_token = Some(new_token);
                let _ = credentials.save(&self.config_path);
                println!("{}", "Credentials validated successfully!".green().bold());
                return Ok(());
            }
        }
        Err("Invalid credentials".into())
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
    use crate::CONFIG_FILE;
    use std::io::Write;

    use super::*;
    use tempfile::tempdir;

    /// Test depends on `save_credentials()`
    #[test]
    fn test_delete_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: Some("testtoken".to_string()),
        };

        let _ = credentials.save(&config_path);

        let saved_data = std::fs::read_to_string(&config_path).unwrap();
        assert!(saved_data.contains("testuser"));
        assert!(saved_data.contains("testpassword"));
        assert!(saved_data.contains("testtoken"));
    }

    #[test]
    fn test_save_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: Some("testtoken".to_string()),
        };

        let _ = credentials.save(&config_path);

        let saved_data = std::fs::read_to_string(&config_path).unwrap();
        let saved_credentials: Credentials = serde_json::from_str(&saved_data).unwrap();

        assert_eq!(saved_credentials.username.unwrap(), "testuser");
        assert_eq!(saved_credentials.password.unwrap(), "testpassword");
        assert_eq!(saved_credentials.access_token.unwrap(), "testtoken");
    }

    /// Set up a temp `CONFIG_FILE` file with test credentials to assert whether `get_credentials()`
    /// can read from the file and return the accurate `username` and `password`
    #[test]
    fn test_load_credentials_with_valid_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_file_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: None,
        };
        let serialized =
            serde_json::to_string(&credentials).expect("Failed to serialize credentials");
        std::fs::create_dir_all(config_file_path.parent().unwrap()).unwrap();
        let mut file = std::fs::File::create(&config_file_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        let result = Credentials::load(&*config_file_path).unwrap();

        assert_eq!(result.username.unwrap(), "testuser");
        assert_eq!(result.password.unwrap(), "testpassword");
    }
}
