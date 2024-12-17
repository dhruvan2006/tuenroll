use crate::api::{self, ApiTrait};
use crate::{ApiError, CliError, CredentialError};
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use keyring::Entry;
use mockall::automock;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::{env, io};
use log::error;

/// Represents user credentials, including username, password, and access token.
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Credentials {
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub access_token: Option<String>,
}

impl Credentials {
    fn save_to_keyring(&self, service: &str) -> Result<(), CredentialError> {
        if let Some(username) = &self.username {
            let entry = Entry::new(service, "username").map_err(CredentialError::KeyringError)?;
            entry
                .set_password(username)
                .map_err(CredentialError::KeyringError)?;
        }

        if let Some(password) = &self.password {
            let entry = Entry::new(service, "password").map_err(CredentialError::KeyringError)?;
            entry
                .set_password(password)
                .map_err(CredentialError::KeyringError)?;
        }

        if let Some(token) = &self.access_token {
            let entry =
                Entry::new(service, "access_token").map_err(CredentialError::KeyringError)?;
            entry
                .set_password(token)
                .map_err(CredentialError::KeyringError)?;
        }
        Ok(())
    }

    pub fn load_from_keyring(service: &str) -> Result<Self, CredentialError> {
        let mut credentials = Self::default()?;

        match Entry::new(service, "username") {
            Ok(entry) => credentials.username = entry.get_password().ok(),
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        match Entry::new(service, "password") {
            Ok(entry) => credentials.password = entry.get_password().ok(),
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        match Entry::new(service, "access_token") {
            Ok(entry) => credentials.access_token = entry.get_password().ok(),
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        Ok(credentials)
    }

    fn delete_from_keyring(service: &str) -> Result<(), CredentialError> {
        match Entry::new(service, "username") {
            Ok(entry) => entry
                .delete_credential()
                .map_err(CredentialError::KeyringError)?,
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        match Entry::new(service, "password") {
            Ok(entry) => entry
                .delete_credential()
                .map_err(CredentialError::KeyringError)?,
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        match Entry::new(service, "access_token") {
            Ok(entry) => entry
                .delete_credential()
                .map_err(CredentialError::KeyringError)?,
            Err(err) => return Err(CredentialError::KeyringError(err)),
        }

        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.username.is_none() || self.password.is_none()
    }

    pub fn default() -> Result<Credentials, CredentialError> {
        Ok(Credentials {
            username: None,
            password: None,
            access_token: None,
        })
    }
}

#[automock]
#[async_trait]
pub trait CredentialManagerTrait<T: ApiTrait + 'static + Sync> {
    async fn get_valid_credentials<F, G>(
        &self,
        loader: F,
        prompt_fn: G,
        show_spinner: bool,
    ) -> Result<Credentials, CliError>
    where
        F: Fn(&str) -> Result<Credentials, CredentialError> + Send + Sync + 'static,
        G: Fn() -> Result<Credentials, CredentialError> + Send + Sync + 'static;
    async fn validate_stored_token(
        &self,
        credentials: &Credentials,
        url: &str,
    ) -> Result<bool, ApiError>;
}

pub struct CredentialManager<T: ApiTrait> {
    api: T,
    service_name: String,
}

impl<T: ApiTrait> CredentialManager<T> {
    pub fn new(api: T, service_name: String) -> Self {
        Self { api, service_name }
    }

    pub fn delete_credentials(&self) -> Result<(), CredentialError> {
        Credentials::delete_from_keyring(self.service_name.as_str())
    }

    pub fn has_credentials(&self) -> Result<bool, CredentialError> {
        Credentials::load_from_keyring(&self.service_name).map(|creds| !creds.is_empty())
    }

    /// Prompt the user for credentials.
    pub fn prompt_for_credentials() -> Result<Credentials, CredentialError> {
        let mut username = String::new();

        print!("Username: ");
        let _ = io::stdout().flush();
        io::stdin()
            .read_line(&mut username)
            .map_err(|e| CredentialError::InputError(e.to_string()))?;

        print!("Password: ");
        let _ = io::stdout().flush();
        let password =
            rpassword::read_password().map_err(|e| CredentialError::InputError(e.to_string()))?;

        Ok(Credentials {
            username: Some(username.trim().to_string()),
            password: Some(password.trim().to_string()),
            access_token: None,
        })
    }

    /// Retrieves valid credentials with an access token.
    /// If the access token is missing or invalid, it fetches a new one and updates the config.
    pub async fn get_valid_credentials<F, G>(
        &self,
        loader: F,
        prompt_fn: G,
        show_spinner: bool,
    ) -> Result<Credentials, CliError>
    where
        F: Fn(&str) -> Result<Credentials, CredentialError>,
        G: Fn() -> Result<Credentials, CredentialError>,
    {
        let mut credentials = loader(self.service_name.as_str()).unwrap_or_default();

        if credentials.is_empty() {
            credentials = prompt_fn()?;
        }

        // Setup spinner
        let pb = if show_spinner {
            Some(self.setup_progress_bar(&mut credentials))
        } else {
            None
        };

        // Validate existing stored access token
        if self
            .validate_stored_token(&credentials, api::REGISTERED_COURSE_URL)
            .await?
        {
            if let Some(pb) = pb {
                self.cleanup_progress_bar(&pb);
            }
            return Ok(credentials);
        }

        // Retrieve new access token if it was expired
        self.retrieve_new_access_token(&mut credentials).await?;
        if let Some(pb) = pb {
            self.cleanup_progress_bar(&pb);
        }
        Ok(credentials)
    }

    pub async fn validate_stored_token(
        &self,
        credentials: &Credentials,
        url: &str,
    ) -> Result<bool, ApiError> {
        if let Some(token) = &credentials.access_token {
            let is_valid = self.api.is_user_authenticated(token, url).await?;
            return Ok(is_valid);
        }
        Ok(false)
    }

    /// Requires you to assure that the `credentials` has Some(username) and Some(password) not None
    async fn retrieve_new_access_token(
        &self,
        credentials: &mut Credentials,
    ) -> Result<(), CliError> {
        // Check if both username and password are available
        let (username, password) = credentials
            .username
            .as_deref()
            .zip(credentials.password.as_deref())
            .ok_or_else(|| CliError::CredentialError(CredentialError::InvalidCredentials))?;

        // Request new access token
        let token = self.api.get_access_token(username, password).await?;
        credentials.access_token = Some(token);
        credentials.save_to_keyring(self.service_name.as_str())?;

        Ok(())
    }

    /// Setup progress bar for long operations.
    fn setup_progress_bar(&self, credentials: &mut Credentials) -> Option<ProgressBar> {
        if env::var("DAEMONIZED").is_ok() || credentials.is_empty() {
            return None;
        }

        let pb = ProgressBar::new_spinner();
        match ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.green} {msg}")
        {
            Ok(style) => {
                pb.set_style(style);
                pb.enable_steady_tick(std::time::Duration::from_millis(100));
                pb.set_message("Validating credentials...");
                Some(pb)
            }
            Err(_) => {
                error!("Error setting progress bar style.");
                None
            }
        }
    }

    /// Cleanup progress bar.
    fn cleanup_progress_bar(&self, pb: &Option<ProgressBar>) {
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    }
}

#[async_trait]
impl<T: ApiTrait + 'static + Sync> CredentialManagerTrait<T> for CredentialManager<T> {
    async fn get_valid_credentials<F, G>(
        &self,
        loader: F,
        prompt_fn: G,
        show_spinner: bool,
    ) -> Result<Credentials, CliError>
    where
        F: Fn(&str) -> Result<Credentials, CredentialError> + Send,
        G: Fn() -> Result<Credentials, CredentialError> + Send,
    {
        self.get_valid_credentials(loader, prompt_fn, show_spinner)
            .await
    }

    async fn validate_stored_token(
        &self,
        credentials: &Credentials,
        url: &str,
    ) -> Result<bool, ApiError> {
        self.validate_stored_token(credentials, url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::MockApiTrait;
    use crate::{CliError, CredentialError};
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
        let empty_credentials = Credentials::default().unwrap();

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
        let credentials = Credentials::default().unwrap();
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
            .returning(|_, _| {
                Err(CliError::CredentialError(
                    CredentialError::InvalidCredentials,
                ))
            });

        let mut credentials = Credentials {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            access_token: None,
        };

        let manager = CredentialManager::new(mock_api, "test_service".to_string());
        let result = manager.retrieve_new_access_token(&mut credentials).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::CredentialError(CredentialError::InvalidCredentials) => {}
            _ => panic!("Expected InvalidCredentials error"),
        }
        assert!(credentials.access_token.is_none());
    }

    // #[tokio::test]
    // async fn test_retrieve_new_access_token_with_network_error() {
    //     let mut mock_api = MockApiTrait::new();
    //     mock_api
    //         .expect_get_access_token()
    //         .with(eq("test_user"), eq("test_password"))
    //         .times(1)
    //         .returning(|_, _| Err(CliError::ApiError(ApiError::NetworkError("Network request failed".to_string()))));
    //
    //     let mut credentials = Credentials {
    //         username: Some("test_user".to_string()),
    //         password: Some("test_password".to_string()),
    //         access_token: None,
    //     };
    //
    //     let manager = CredentialManager::new(mock_api, "test_service".to_string());
    //     let result = manager.retrieve_new_access_token(&mut credentials).await;
    //
    //     assert!(result.is_err());
    //     assert_eq!(result.unwrap_err().to_string(), "Network request error");
    // }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_delete_credentials() {
        let test_service = generate_unique_service();
        let credentials = setup_test_credentials();

        save_test_credentials(&test_service, &credentials);

        // Delete credentials
        let manager = CredentialManager::new(Api::new().unwrap(), test_service.clone());
        let _ = manager.delete_credentials();

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

        let credential_manager = CredentialManager::new(Api::new().unwrap(), service.clone());

        // Test if has_credentials returns true
        assert!(credential_manager.has_credentials().unwrap());

        cleanup_service(&service);
    }

    #[test]
    fn test_has_credentials_with_empty_credentials() {
        let service = generate_unique_service();
        let credentials = Credentials::default().unwrap();
        save_test_credentials(&service, &credentials);

        let credential_manager = CredentialManager::new(Api::new().unwrap(), service.clone());

        // Test if has_credentials returns false
        assert!(!credential_manager.has_credentials().unwrap());

        cleanup_service(&service);
    }

    #[test]
    fn test_has_credentials_with_missing_file() {
        let service = generate_unique_service();

        let credential_manager = CredentialManager::new(Api::new().unwrap(), service.clone());

        // Test if has_credentials returns false when the file is missing
        assert!(!credential_manager.has_credentials().unwrap());
    }

    #[test]
    fn test_setup_progress_bar_with_daemonized_env() {
        env::set_var("DAEMONIZED", "1");
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let mut credentials = Credentials::default().unwrap();
        let pb = manager.setup_progress_bar(&mut credentials);
        assert!(pb.is_none());

        env::remove_var("DAEMONIZED");
    }

    #[test]
    fn test_setup_progress_bar_with_empty_credentials() {
        let mock_api = MockApiTrait::new();
        let manager = CredentialManager::new(mock_api, "test_service".to_string());

        let mut credentials = Credentials::default().unwrap();
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

        let mock_loader = |_service: &str| -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("valid_token".to_string()),
            })
        };

        let mock_prompt = || -> Result<Credentials, CredentialError> { Credentials::default() };

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

        let mock_loader = |_service: &str| -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("invalid_token".to_string()),
            })
        };

        let mock_prompt = || -> Result<Credentials, CredentialError> { Credentials::default() };

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

        let mock_loader: Box<
            dyn Fn(&str) -> Result<Credentials, CredentialError> + Send + Sync + 'static,
        > = Box::new(|_| -> Result<Credentials, CredentialError> { Credentials::default() });

        let mock_prompt: Box<
            dyn Fn() -> Result<Credentials, CredentialError> + Send + Sync + 'static,
        > = Box::new(|| -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("valid_token".to_string()),
            })
        });

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

        let mock_loader = |_service: &str| -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: None, // No access token.
            })
        };

        let mock_prompt = || -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("new_valid_token".to_string()),
            })
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

        let mock_loader = |_service: &str| -> Result<Credentials, CredentialError> {
            Credentials::default() // Empty credentials.
        };

        let mock_prompt = || -> Result<Credentials, CredentialError> {
            Ok(Credentials {
                username: Some("test_user".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("new_valid_token".to_string()),
            })
        };

        let result = manager
            .get_valid_credentials(mock_loader, mock_prompt, true)
            .await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.username, Some("test_user".to_string()));
        assert_eq!(creds.access_token, Some("new_valid_token".to_string()));
    }

    // #[tokio::test]
    // async fn test_get_valid_credentials_with_network_error() {
    //     let mut mock_api = MockApiTrait::new();
    //
    //     // Simulate a network error on token retrieval.
    //     mock_api
    //         .expect_is_user_authenticated()
    //         .with(eq("invalid_token"), always())
    //         .returning(|_, _| Ok(false));
    //
    //     mock_api
    //         .expect_get_access_token()
    //         .with(eq("test_user"), eq("test_password"))
    //         .returning(|_, _| Err(CliError::ApiError(ApiError::NetworkError("Network request failed".to_string()))));
    //
    //     let service_name = generate_unique_service();
    //     let manager = CredentialManager::new(mock_api, service_name);
    //
    //     let mock_loader = |_service: &str| -> Result<Credentials, Box<dyn Error>> {
    //         Ok(Credentials {
    //             username: Some("test_user".to_string()),
    //             password: Some("test_password".to_string()),
    //             access_token: Some("invalid_token".to_string()),
    //         })
    //     };
    //
    //     let mock_prompt = || -> Credentials { Credentials::default().unwrap() };
    //
    //     let result = manager
    //         .get_valid_credentials(mock_loader, mock_prompt, true)
    //         .await;
    //     assert!(result.is_err());
    //     assert_eq!(
    //         result.unwrap_err().to_string(),
    //         "Network request error".to_string()
    //     );
    // }
}
