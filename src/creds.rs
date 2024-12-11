use indicatif::{ProgressBar, ProgressStyle};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;
use std::{env, io};

use crate::api::{self, ApiTrait};

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

    pub fn load_from_keyring(service: &str) -> Result<Self, Box<dyn Error>> {
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
        self.username.is_none() || self.password.is_none()
    }
}

pub struct CredentialManager<T: ApiTrait> {
    api: T,
    service_name: String,
}

impl<T: ApiTrait> CredentialManager<T> {
    pub fn new(api: T, service_name: String) -> Self {
        Self { api, service_name }
    }

    pub fn delete_credentials(&self) {
        let _ = Credentials::delete_from_keyring(self.service_name.as_str());
    }

    pub fn has_credentials(&self) -> bool {
        Credentials::load_from_keyring(&self.service_name)
            .map(|creds| !creds.is_empty())
            .unwrap_or(false)
    }

    /// Prompt the user for credentials.
    pub fn prompt_for_credentials() -> Credentials {
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

    /// Retrieves valid credentials with an access token.
    /// If the access token is missing or invalid, it fetches a new one and updates the config.
    pub async fn get_valid_credentials<F, G>(
        &self,
        loader: F,
        prompt_fn: G,
        show_spinner: bool,
    ) -> Result<Credentials, Box<dyn Error>>
    where
        F: Fn(&str) -> Result<Credentials, Box<dyn Error>>,
        G: Fn() -> Credentials,
    {
        let mut credentials = loader(self.service_name.as_str()).unwrap_or_default();

        if credentials.is_empty() {
            credentials = prompt_fn();
        }

        let pb = if show_spinner {
            Some(self.setup_progress_bar(&mut credentials))
        } else {
            None
        };

        if self
            .validate_stored_token(&credentials, api::REGISTERED_COURSE_URL)
            .await?
        {
            if let Some(pb) = pb {
                self.cleanup_progress_bar(&pb);
            }
            return Ok(credentials);
        }

        if let Err(e) = self.retrieve_new_access_token(&mut credentials).await {
            if let Some(pb) = pb {
                self.cleanup_progress_bar(&pb);
            }
            if e.to_string().contains("Network request error") {
                Err("Network request error".into())
            } else {
                Err(e)
            }
        } else {
            if let Some(pb) = pb {
                self.cleanup_progress_bar(&pb);
            }
            Ok(credentials)
        }
    }

    pub async fn validate_stored_token(
        &self,
        credentials: &Credentials,
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

    /// Requires you to assure that the `credentials` has Some(username) and Some(password) not None
    async fn retrieve_new_access_token(
        &self,
        credentials: &mut Credentials,
    ) -> Result<(), Box<dyn Error>> {
        // Request new access_token
        if let (Some(username), Some(password)) = (&credentials.username, &credentials.password) {
            let result = self.api.get_access_token(username, password).await;
            return if let Ok(token) = result {
                credentials.access_token = Some(token);
                let _ = credentials.save_to_keyring(self.service_name.as_str());
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

        Err("Missing credentials".into())
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
    use crate::api::MockApiTrait;
    use api::Api;
    use keyring::Entry;
    use mockall::predicate::{always, eq};
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

        // Give time for the OS to save keyring
        std::thread::sleep(std::time::Duration::from_secs(1));
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

        // Give time for the OS to save keyring
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_save_to_keyring_success() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

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

        verify_credentials_absence(&test_service);

        cleanup_service(&test_service);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_delete_credentials_from_keyring() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

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

    #[tokio::test]
    async fn test_validate_stored_token_with_valid_token() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_is_user_authenticated()
            .with(eq("valid_token"), eq("/test"))
            .times(1)
            .returning(|_, _| Ok(true));

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("valid_token".to_string()),
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let result = manager
            .validate_stored_token(&mut credentials, "/test")
            .await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_stored_token_with_expired_token() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_is_user_authenticated()
            .with(eq("expired_token"), eq("/test"))
            .times(1)
            .returning(|_, _| Ok(false));

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: Some("expired_token".to_string()),
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let result = manager
            .validate_stored_token(&mut credentials, "/test")
            .await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_stored_token_with_none_token() {
        let mock_api = MockApiTrait::new();

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());
        let result = manager
            .validate_stored_token(&mut credentials, "/test")
            .await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_valid_creds() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .times(1)
            .returning(|_, _| Ok("access_token".to_string()));

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let test_service = generate_unique_service();
        let manager = CredentialManager::new(mock_api, test_service);

        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_ok());
        assert!(credentials.access_token.is_some());
        assert_eq!(credentials.access_token.unwrap(), "access_token");
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_with_invalid_creds() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .times(1)
            .returning(|_, _| Err("authentication failed".into()));

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());
        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid credentials");
        assert!(credentials.access_token.is_none());
    }

    #[tokio::test]
    async fn test_retrieve_new_access_token_with_network_error() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .times(1)
            .returning(|_, _| Err("error sending request".into()));

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());
        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Network request error");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_delete_credentials() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

        // Delete credentials
        let manager = CredentialManager::new(Api::new(), test_service.clone());
        manager.delete_credentials();

        verify_credentials_absence(&test_service);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_has_credentials_non_empty_keyring() {
        let service = generate_unique_service();
        let credentials = setup_test_credentials();
        save_test_credentials(&service, &credentials);

        let credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_pass".to_string()),
            access_token: Some("token123".to_string()),
        };

        let _ = credentials.save_to_keyring(&service);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let credential_manager = CredentialManager::new(Api::new(), service.clone());

        // Test if has_credentials returns true
        assert!(credential_manager.has_credentials());

        cleanup_service(&service);
    }

    #[test]
    fn test_has_credentials_with_empty_credentials() {
        let service = generate_unique_service();
        let credentials = Credentials::default();
        save_test_credentials(&service, &credentials);

        let credential_manager = CredentialManager::new(Api::new(), service.clone());

        // Test if has_credentials returns false
        assert!(!credential_manager.has_credentials());

        cleanup_service(&service);
    }

    #[test]
    fn test_has_credentials_with_missing_file() {
        let service = generate_unique_service();

        let credential_manager = CredentialManager::new(Api::new(), service.clone());

        // Test if has_credentials returns false when the file is missing
        assert!(!credential_manager.has_credentials());
    }

    #[test]
    fn test_setup_progress_bar_with_daemonized_env() {
        env::set_var("DAEMONIZED", "1");
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let mut credentials = Credentials::default();
        let pb = manager.setup_progress_bar(&mut credentials);
        assert!(pb.is_none());

        env::remove_var("DAEMONIZED");
    }

    #[test]
    fn test_setup_progress_bar_with_empty_credentials() {
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let mut credentials = Credentials::default();
        let pb = manager.setup_progress_bar(&mut credentials);
        assert!(pb.is_none());
    }

    #[test]
    fn test_setup_progress_bar_with_valid_credentials() {
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let mut credentials = Credentials {
            username: Some("user".to_string()),
            password: Some("password".to_string()),
            access_token: Some("token".to_string()),
        };

        let pb = manager.setup_progress_bar(&mut credentials);
        assert!(pb.is_some());
    }

    #[test]
    fn test_cleanup_progress_bar() {
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let pb = ProgressBar::new_spinner();
        pb.set_message("Validating credentials...");
        let pb_option = Some(pb);

        manager.cleanup_progress_bar(&pb_option);
        assert!(pb_option.unwrap().is_finished());
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_valid_token() {
        let mut mock_api = MockApiTrait::new();
        mock_api
            .expect_is_user_authenticated()
            .with(eq("valid_token"), always())
            .returning(|_, _| Ok(true));

        let service_name = generate_unique_service();

        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("valid_token".to_string()),
            })
        };

        let mock_prompt = || -> Credentials { Credentials::default() };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("valid_token".to_string()));
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_invalid_token() {
        let mut mock_api = MockApiTrait::new();

        // First call to `is_user_authenticated` with an invalid token.
        mock_api
            .expect_is_user_authenticated()
            .with(eq("invalid_token"), always())
            .returning(|_, _| Ok(false));

        // Call to `get_access_token` returns a new valid token.
        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .returning(|_, _| Ok("new_valid_token".to_string()));

        let service_name = generate_unique_service();
        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("invalid_token".to_string()),
            })
        };

        let mock_prompt = || -> Credentials { Credentials::default() };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("new_valid_token".to_string()));
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_no_credentials_from_loader() {
        let mut mock_api = MockApiTrait::new();

        mock_api
            .expect_is_user_authenticated()
            .with(eq("valid_token"), always())
            .returning(|_, _| Ok(true));

        let service_name = generate_unique_service();

        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials::default()) // Returns no credentials.
        };

        let mock_prompt = || -> Credentials {
            Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("valid_token".to_string()),
            }
        };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("valid_token".to_string()));
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_missing_access_token() {
        let mut mock_api = MockApiTrait::new();

        // Test if access token is missing and loader does not return one.
        mock_api
            .expect_is_user_authenticated()
            .with(eq("missing_token"), always())
            .returning(|_, _| Ok(false));

        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .returning(|_, _| Ok("new_valid_token".to_string()));

        let service_name = generate_unique_service();
        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: None, // No access token.
            })
        };

        let mock_prompt = || -> Credentials {
            Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("new_valid_token".to_string()),
            }
        };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("new_valid_token".to_string()));
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_empty_credentials() {
        let mut mock_api = MockApiTrait::new();

        // No credentials loaded from loader.
        mock_api
            .expect_is_user_authenticated()
            .with(eq("empty_token"), always())
            .returning(|_, _| Ok(false));

        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .returning(|_, _| Ok("new_valid_token".to_string()));

        mock_api
            .expect_is_user_authenticated()
            .with(eq("new_valid_token"), always())
            .returning(|_, _| Ok(true));

        let service_name = generate_unique_service();
        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials::default()) // Empty credentials.
        };

        let mock_prompt = || -> Credentials {
            Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("new_valid_token".to_string()),
            }
        };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("new_valid_token".to_string()));
    }

    #[tokio::test]
    async fn test_get_valid_credentials_with_network_error() {
        let mut mock_api = MockApiTrait::new();

        // Simulate a network error on token retrieval.
        mock_api
            .expect_is_user_authenticated()
            .with(eq("invalid_token"), always())
            .returning(|_, _| Ok(false));

        mock_api
            .expect_get_access_token()
            .with(eq("test_user"), eq("test_password"))
            .returning(|_, _| Err("error sending request".into()));

        let service_name = generate_unique_service();
        let manager = CredentialManager::new(mock_api, service_name);

        let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("invalid_token".to_string()),
            })
        };

        let mock_prompt = || -> Credentials { Credentials::default() };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Network request error".to_string()
        );
    }
}
