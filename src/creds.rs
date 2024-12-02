use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;
use std::{env, io};

use crate::api::{self, Api};

/// Represents user credentials, including username, password, and access token.
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Credentials {
    username: Option<String>,
    password: Option<String>,
    pub access_token: Option<String>,
}

impl Credentials {
    fn save_to_keyring(&self, service: &str) -> Result<(), Box<dyn Error>> {
        if let Some(username) = &self.username {
            let entry = Entry::new(service, "username")?;
            entry.set_password(username)?;
        }

        if let Some(password) = &self.password {
            let entry = Entry::new(service, "password")?;
            entry.set_password(password)?;
        }

        if let Some(token) = &self.access_token {
            let entry = Entry::new(service, "access_token")?;
            entry.set_password(token)?;
        }
        Ok(())
    }

    fn load_from_keyring(service: &str) -> Result<Self, Box<dyn Error>> {
        let mut credentials = Self::default();

        if let Ok(entry) = Entry::new(service, "username") {
            credentials.username = entry.get_password().ok();
        }

        if let Ok(entry) = Entry::new(service, "password") {
            credentials.password = entry.get_password().ok();
        }

        if let Ok(entry) = Entry::new(service, "access_token") {
            credentials.access_token = entry.get_password().ok();
        }

        Ok(credentials)
    }

    fn delete_from_keyring(service: &str) -> Result<(), Box<dyn Error>> {
        if let Ok(entry) = Entry::new(service, "username") {
            let _ = entry.delete_credential();
        }

        if let Ok(entry) = Entry::new(service, "password") {
            let _ = entry.delete_credential();
        }

        if let Ok(entry) = Entry::new(service, "access_token") {
            let _ = entry.delete_credential();
        }

        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.username.is_none() && self.password.is_none() && self.access_token.is_none()
    }
}

pub struct CredentialManager {
    api: Api,
}

impl CredentialManager {
    const SERVICE_NAME: &'static str = "tuenroll";

    pub fn new() -> Self {
        Self { api: Api::new() }
    }

    pub fn delete_credentials(&self) {
        let _ = Credentials::delete_from_keyring(Self::SERVICE_NAME);
    }

    pub fn has_credentials(&self) -> bool {
        Credentials::load(&self.config_path)
            .map(|creds| !creds.is_empty())
            .unwrap_or(false)
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
        let mut credentials =
            Credentials::load_from_keyring(Self::SERVICE_NAME).unwrap_or_default();

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
                if e.to_string().contains("Network request error") {
                    return Err("Network request error;".into());
                }
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
            let is_valid = self
                .api
                .is_user_authenticated(token, url)
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
            let result = self.api.get_access_token(username, password).await;
            return if let Ok(token) = result {
                credentials.access_token = Some(token);
                let _ = credentials.save_to_keyring(Self::SERVICE_NAME);
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
    use super::*;
    use keyring::Entry;
    use uuid::Uuid;

    fn generate_unique_service() -> String {
        format!("test_service_{}", Uuid::new_v4())
    }

    fn setup_test_credentials() -> Credentials {
        Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("test_token".to_string()),
        }
    }

    fn save_test_credentials(service: &str, credentials: &Credentials) {
        credentials
            .save_to_keyring(service)
            .expect("Failed to save test credentials");
    }

    fn verify_credentials_absence(service: &str) {
        assert!(Entry::new(service, "username")
            .unwrap()
            .get_password()
            .is_err());
        assert!(Entry::new(service, "password")
            .unwrap()
            .get_password()
            .is_err());
        assert!(Entry::new(service, "access_token")
            .unwrap()
            .get_password()
            .is_err());
    }

    fn cleanup_service(service: &str) {
        let _ = Credentials::delete_from_keyring(service);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_save_to_keyring_success() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

        std::thread::sleep(std::time::Duration::from_secs(1));

        // Verify credentials were saved
        assert_eq!(
            Entry::new(&test_service, "username")
                .unwrap()
                .get_password()
                .unwrap(),
            "test_user"
        );
        assert_eq!(
            Entry::new(&test_service, "password")
                .unwrap()
                .get_password()
                .unwrap(),
            "test_password"
        );
        assert_eq!(
            Entry::new(&test_service, "access_token")
                .unwrap()
                .get_password()
                .unwrap(),
            "test_token"
        );

        cleanup_service(&test_service);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_load_credentials_from_keyring_success() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

        std::thread::sleep(std::time::Duration::from_millis(100));

        // Load credentials from the keyring
        let loaded_credentials = Credentials::load_from_keyring(&test_service).unwrap();
        assert_eq!(loaded_credentials.username, credentials.username);
        assert_eq!(loaded_credentials.password, credentials.password);
        assert_eq!(loaded_credentials.access_token, credentials.access_token);

        cleanup_service(&test_service);
    }

    #[test]
    fn test_load_credentials_from_keyring_missing() {
        let test_service = generate_unique_service();
        cleanup_service(&test_service);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let loaded_credentials = Credentials::load_from_keyring(&test_service).unwrap();

        assert!(loaded_credentials.username.is_none());
        assert!(loaded_credentials.password.is_none());
        assert!(loaded_credentials.access_token.is_none());
    }

    #[test]
    fn test_save_empty_credentials_to_keyring() {
        let test_service = generate_unique_service();
        let empty_credentials = Credentials::default();

        save_test_credentials(&test_service, &empty_credentials);

        std::thread::sleep(std::time::Duration::from_secs(1));

        verify_credentials_absence(&test_service);

        cleanup_service(&test_service);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_delete_credentials_from_keyring() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

        std::thread::sleep(std::time::Duration::from_secs(1));

        // Delete credentials
        cleanup_service(&test_service);

        verify_credentials_absence(&test_service);
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
        let credentials = setup_test_credentials();
        assert!(!credentials.is_empty());
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

        let manager = CredentialManager::new();

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

        let manager = CredentialManager::new();
        let result = manager.validate_stored_token(&mut credentials, "").await;
        assert!(!result.unwrap());
    }

    // TODO: Use mocked api
    // #[tokio::test]
    // async fn test_retrieve_new_access_token_invalid_url() {
    //     let mut credentials = Credentials {
    //         username: Some("valid_user".to_string()),
    //         password: Some("valid_pass".to_string()),
    //         ..Default::default()
    //     };

    //     let manager =
    //         CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

    //     let result = manager.retrieve_new_access_token(&mut credentials).await;

    //     assert!(result.is_err());
    // }

    // #[tokio::test]
    // async fn test_retrieve_new_access_token_invalid_password() {
    //     let mut credentials = Credentials {
    //         username: Some("valid_user".to_string()),
    //         password: Some("incorrect".to_string()),
    //         ..Default::default()
    //     };

    //     let manager =
    //         CredentialManager::new(PathBuf::from_str("").expect("Failed to create PathBuf"));

    //     let result = manager.retrieve_new_access_token(&mut credentials).await;

    //     assert!(result.is_err());
    //     assert!(credentials.access_token.is_none());
    // }

    #[tokio::test]
    async fn test_retrieve_new_access_token_missing_creds() {
        let mut credentials = Credentials::default();

        let manager = CredentialManager::new();

        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        assert!(credentials.is_empty());
    }

    #[test]
    fn test_has_credentials_with_non_empty_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("credentials.json");

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_pass".to_string()),
            access_token: Some("token123".to_string()),
        };

        credentials.save(&config_path).unwrap();

        let credential_manager = CredentialManager {
            config_path: config_path.clone(),
            api: Api::new(),
        };

        // Test if has_credentials returns true
        assert!(credential_manager.has_credentials());
    }

    #[test]
    fn test_has_credentials_with_empty_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("credentials.json");

        let credentials = Credentials::default();

        credentials.save(&config_path).unwrap();

        let credential_manager = CredentialManager {
            config_path: config_path.clone(),
            api: Api::new(),
        };

        // Test if has_credentials returns false
        assert!(!credential_manager.has_credentials());
    }

    #[test]
    fn test_has_credentials_with_missing_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("non_existent_credentials.json");

        let credential_manager = CredentialManager {
            config_path: config_path.clone(),
            api: Api::new(),
        };

        // Test if has_credentials returns false when the file is missing
        assert!(!credential_manager.has_credentials());
    }
}
