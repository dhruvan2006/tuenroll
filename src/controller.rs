use crate::api::ApiTrait;
use crate::creds::{CredentialManager, CredentialManagerTrait, Credentials};
use crate::{api, get_config_path, store_last_check_time, CliError, CredentialError};
use colored::Colorize;
use log::{error, info};
use std::{thread, time};

pub struct Controller<T, F, G, H> {
    api: T,
    exit_fn: F,
    manager: G,
    is_loop: bool,
    is_boot: bool,
    show_notif_fn: H,
}

impl<
        T: ApiTrait + Sync + 'static,
        F: FnOnce(i32) + Clone + Send,
        G: CredentialManagerTrait<T>,
        H: FnMut(&str),
    > Controller<T, F, G, H>
{
    pub fn new(
        api: T,
        exit_fn: F,
        manager: G,
        is_loop: bool,
        is_boot: bool,
        show_notif_fn: H,
    ) -> Self {
        Controller {
            api,
            exit_fn,
            manager,
            is_loop,
            is_boot,
            show_notif_fn,
        }
    }

    pub async fn run_loop(&mut self, interval_secs: u32, sleep_interval_secs: u32) {
        let result = self.run_auto_sign_up().await;
        self.handle_request(result, true, false);

        let mut start_time = std::time::SystemTime::now();
        loop {
            info!("Checking whether time interval is completed");

            // Safely handle the result of `duration_since()`
            if let Ok(duration) = std::time::SystemTime::now().duration_since(start_time) {
                if duration.as_secs() >= interval_secs as u64 {
                    info!("Running auto sign up");
                    let result = self.run_auto_sign_up().await;
                    self.handle_request(result, false, true);
                    start_time = std::time::SystemTime::now();
                }
            } else {
                // Very unlikely that duration_since fails, but we want to avoid unwraps()
                error!("Failed to calculate time interval. Retrying...");
            }

            tokio::time::sleep(time::Duration::from_secs(sleep_interval_secs as u64)).await;
        }
    }

    pub async fn get_credentials(&mut self) -> Credentials {
        let credentials;

        loop {
            let request = self.manager.get_valid_credentials(
                Credentials::load_from_keyring,
                CredentialManager::<T>::prompt_for_credentials,
                !self.is_boot,
            );
            // don't exit or send notif
            if let Some(data) = self.handle_request(request.await, !self.is_loop, false) {
                credentials = data;
                if !self.is_boot {
                    println!("{}", "Credentials validated successfully!".green().bold());
                }
                break;
            }
        }

        credentials
    }

    /// Runs the auto signup fully once
    /// Gets the credentials, the access token
    /// Automatically signs up for all the tests
    /// Prints the result of execution
    pub async fn run_auto_sign_up(&mut self) -> Result<(), CliError> {
        // Check if credentials exist
        let credentials = self
            .manager
            .get_valid_credentials(
                Credentials::load_from_keyring,
                Credentials::default,
                !self.is_loop,
            )
            .await?;

        // Check if creds are valid
        if !self
            .manager
            .validate_stored_token(&credentials, api::REGISTERED_COURSE_URL)
            .await?
        {
            return Err(CliError::from(CredentialError::InvalidCredentials));
        }

        // Get the access_token, should not fail
        let access_token = credentials
            .access_token
            .ok_or_else(|| CredentialError::InvalidCredentials)?;

        // Register for tests
        let registration_result = self
            .api
            .register_for_tests(
                &access_token,
                api::REGISTERED_COURSE_URL,
                api::TEST_COURSE_URL,
                api::TEST_REGISTRATION_URL,
            )
            .await?;

        // Process registration results
        let course_korte_naam_result: Vec<String> = registration_result
            .iter()
            .map(|test_list| test_list.cursus_korte_naam.clone())
            .collect();

        if course_korte_naam_result.is_empty() {
            info!("No exams were enrolled for.");
        } else {
            info!(
                "Successfully enrolled for the following exams: {:?}",
                course_korte_naam_result
            );
            // Send desktop notification
            for course_name in course_korte_naam_result {
                (self.show_notif_fn)(&format!(
                    "You have been successfully registered for the exam: {}",
                    course_name
                ));
            }
        }

        // Store the last check time
        store_last_check_time(get_config_path)?;

        Ok(())
    }

    fn handle_request<R>(
        &mut self,
        request: Result<R, CliError>,
        exit: bool,
        notif: bool,
    ) -> Option<R> {
        match request {
            Ok(data) => Some(data),
            Err(e) => {
                match &e {
                    CliError::ApiError(api_err) => {
                        // Handle API errors
                        // 1. `Run`   -> Exit
                        // 2. `Start` -> Retry every 5 seconds
                        // 3. `Boot`  -> Don't print + Retry every 5 seconds
                        error!("{}", api_err);
                        if !self.is_boot {
                            eprintln!("{}", format!("{}", api_err).red().bold());
                        }
                        if !self.is_loop && exit {
                            self.exit_fn.clone()(0); // Exit if `run` and api error
                        }
                        thread::sleep(time::Duration::from_secs(5));
                    }
                    CliError::CredentialError(cred_err) => {
                        // Handle credential errors
                        // 1. `Run`   -> Exit
                        // 2. `Start` -> Show notification
                        // 3. `Boot`  -> Don't print + Show notification
                        error!("{}", cred_err);
                        if !self.is_boot {
                            eprintln!("{}", format!("{}", cred_err).red().bold());
                        }
                        if !self.is_loop && exit {
                            self.exit_fn.clone()(1); // Exit if `run` and credentials error
                        } else if notif {
                            (self.show_notif_fn)(
                                "Your credentials are invalid. Run tuenroll start again",
                            );
                        }
                    }
                    // Don't believe we can fix: ConfigError, IOError & JsonError
                    CliError::ConfigError(e) => {
                        error!("Config error: {}", e);
                    }
                    CliError::IoError(e) => {
                        error!("IO error: {}", e);
                    }
                    CliError::JsonError(e) => {
                        error!("JSON error: {}", e);
                    }
                }

                None
            }
        }
    }
}

#[cfg(test)]
mod tests {

    /// Tests for `get_credentials()`
    mod get_credentials_test {
        use crate::api::MockApiTrait;
        use crate::controller::Controller;
        use crate::creds::{Credentials, MockCredentialManagerTrait};
        use crate::{CliError, CredentialError};

        /// Test when credential retrieval first fails then success
        #[tokio::test]
        async fn test_get_credentials_success() {
            let mock_api = MockApiTrait::new();
            let mut mock_manager = MockCredentialManagerTrait::default();

            // First two attempts fail, then succeed on the third.
            let mock_credentials = Credentials {
                username: Some("test_username".to_string()),
                password: Some("test_password".to_string()),
                access_token: Some("valid_token".to_string()),
            };
            let expected_credentials = mock_credentials.clone();

            mock_manager
                .expect_get_valid_credentials()
                .returning(|_, _, _| Err(CliError::from(CredentialError::InvalidCredentials)))
                .times(2); // simulate two failures
            mock_manager
                .expect_get_valid_credentials()
                .returning(move |_, _, _| Ok(mock_credentials.clone()))
                .times(1); // simulate one success

            let mut controller = Controller {
                api: mock_api,
                exit_fn: |_| {},
                manager: mock_manager,
                is_loop: true,
                is_boot: false,
                show_notif_fn: |_: &str| {},
            };
            let result = controller.get_credentials().await;

            assert_eq!(expected_credentials, result);
        }
    }

    /// Tests for `handle_request()`
    mod handle_request_tests {
        use crate::api::MockApiTrait;
        use crate::controller::Controller;
        use crate::creds::MockCredentialManagerTrait;
        use crate::{ApiError, CliError, CredentialError};
        use std::process::exit;
        use std::sync::mpsc;

        /// Test when request is successful (Ok)
        #[test]
        fn test_handle_request_ok() {
            let request: Result<i32, CliError> = Ok(42);
            let mut controller = Controller {
                api: MockApiTrait::new(),
                exit_fn: |code: i32| exit(code),
                manager: MockCredentialManagerTrait::default(),
                is_loop: false,
                is_boot: false,
                show_notif_fn: |_: &str| {},
            };
            let response = controller.handle_request(request, true, true);

            assert_eq!(response, Some(42)); // should just return the data
        }

        /// Test for a request with `Invalid credentials` Error
        #[test]
        fn test_handle_request_invalid_credentials() {
            let request: Result<i32, CliError> = Err(CliError::CredentialError(
                CredentialError::InvalidCredentials,
            ));

            let (sender, receiver) = mpsc::channel();
            let mock_exit_fn = move |code: i32| sender.send(code).unwrap();

            let mut controller = Controller {
                api: MockApiTrait::new(),
                exit_fn: mock_exit_fn,
                manager: MockCredentialManagerTrait::default(),
                is_loop: false,
                is_boot: false,
                show_notif_fn: |_: &str| {},
            };
            let response = controller.handle_request(request, true, true);

            assert_eq!(response, None); // Should return None

            let exit_code = receiver.recv().unwrap();
            assert_eq!(exit_code, 1); // Exit code should be `1`
        }

        /// Test request with `Network Error` when called on `Run` (is_loop = false, boot = false)
        #[test]
        fn test_handle_request_run_case() {
            let request: Result<i32, CliError> = Err(CliError::ApiError(
                ApiError::InvalidResponse("Network request error".to_string()),
            ));
            let (sender, receiver) = mpsc::channel();
            let mock_exit_fn = move |code: i32| sender.send(code).unwrap();

            let mut controller = Controller {
                api: MockApiTrait::new(),
                exit_fn: mock_exit_fn,
                manager: MockCredentialManagerTrait::default(),
                is_loop: false,
                is_boot: false,
                show_notif_fn: |_: &str| {},
            };
            let response = controller.handle_request(request, true, true);
            assert_eq!(response, None); // Should return None

            // Ensure exit_fn is called with code 0 for 'Network error'
            let exit_code = receiver.recv().unwrap();
            assert_eq!(exit_code, 0); // Exit code should be 0
        }

        /// Test request with `Network Error` when called on `Start` (is_loop = true, boot = false)
        #[test]
        fn test_handle_request_start_case() {
            let request: Result<i32, CliError> = Err(CliError::ApiError(
                ApiError::InvalidResponse("Network request error".to_string()),
            ));
            let (sender, receiver) = mpsc::channel();
            let mock_exit_fn = move |code: i32| sender.send(code).unwrap();

            let mut controller = Controller {
                api: MockApiTrait::new(),
                exit_fn: mock_exit_fn,
                manager: MockCredentialManagerTrait::default(),
                is_loop: true,
                is_boot: false,
                show_notif_fn: |_: &str| {},
            };
            let response = controller.handle_request(request, true, true);
            assert_eq!(response, None); // Should return None (error occurs)

            // Ensure exit_fn is not called since we're looping
            let exit_result = receiver.recv_timeout(std::time::Duration::from_secs(1));
            assert!(exit_result.is_err());
        }

        /// Test request with `Network Error` when called on `Boot` (is_loop = true, boot = true)
        #[test]
        fn test_handle_request_boot_case() {
            let request: Result<i32, CliError> = Err(CliError::ApiError(
                ApiError::InvalidResponse("Network request error".to_string()),
            ));
            let (sender, receiver) = mpsc::channel();
            let mock_exit_fn = move |code: i32| sender.send(code).unwrap();

            let mut controller = Controller {
                api: MockApiTrait::new(),
                exit_fn: mock_exit_fn,
                manager: MockCredentialManagerTrait::default(),
                is_loop: true,
                is_boot: true,
                show_notif_fn: |_: &str| {},
            };
            let response = controller.handle_request(request, true, true);
            assert_eq!(response, None); // Should return None

            // Ensure exit_fn is not called due to looping
            let exit_result = receiver.recv_timeout(std::time::Duration::from_secs(1));
            assert!(exit_result.is_err()); // Should time out without calling exit_fn
        }
    }

    /// Tests for `run_auto_sign_up()`
    mod run_auto_sign_up_tests {
        use crate::api::ApiTrait;
        use crate::controller::Controller;
        use crate::creds::{CredentialManagerTrait, Credentials};
        use crate::models::TestList;
        use crate::{ApiError, CliError, CredentialError};
        use async_trait::async_trait;
        use mockall::mock;
        use mockall::predicate::*;

        // Mock implementations for testing
        mock! {
            Api {}
            #[async_trait]
            impl ApiTrait for Api {
                async fn is_user_authenticated(
                    &self,
                    access_token: &str,
                    url: &str,
                ) -> Result<bool, ApiError>;

                async fn get_access_token(
                    &self,
                    username: &str,
                    password: &str,
                ) -> Result<String, CliError>;

                async fn register_for_tests(
                    &self,
                    access_token: &str,
                    registered_course_url: &str,
                    test_course_url: &str,
                    test_registration_url: &str,
                ) -> Result<Vec<TestList>, CliError>;
            }
        }

        impl Clone for MockApi {
            fn clone(&self) -> Self {
                MockApi::new()
            }
        }

        mock! {
            CredentialManager {}
            #[async_trait]
            impl CredentialManagerTrait<MockApi> for CredentialManager {
                // fn new(api: MockApi, service_name: String) -> Self;
                // fn delete_credentials(&self);
                // fn has_credentials(&self) -> bool;
                // fn prompt_for_credentials() -> Credentials;

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
        }

        // /// Test successful run with multiple open exams
        // #[tokio::test]
        // #[cfg(target_os = "windows")]
        // async fn test_run_auto_sign_up_successful_multiple_exams() {
        //     let mut mock_api = MockApi::new();
        //     let mut mock_manager = MockCredentialManager::default();

        //     // Has valid access_token
        //     let mock_credentials = Credentials {
        //         access_token: Some("valid_token".to_string()),
        //         ..Default::default()
        //     };
        //     mock_manager
        //         .expect_get_valid_credentials()
        //         .return_once(move |_, _, _| Ok(mock_credentials.clone()));

        //     mock_manager
        //         .expect_validate_stored_token()
        //         .return_once(|_, _| Ok(true));

        //     // Returns a list of courses to sign up for
        //     let test_list = vec![
        //         TestList {
        //             cursus_korte_naam: "MATH101".to_string(),
        //             ..Default::default()
        //         },
        //         TestList {
        //             cursus_korte_naam: "CS102".to_string(),
        //             ..Default::default()
        //         },
        //     ];
        //     mock_api
        //         .expect_register_for_tests()
        //         .return_once(move |_, _, _, _| Ok(test_list.clone()));

        //     // Dummy exit function
        //     let exit_fn = |_: i32| {};

        //     // Create a spy for the notif_fn
        //     let mut notif_fn_called_with = Vec::new();
        //     let notif_fn = |course_name: &str| {
        //         notif_fn_called_with.push(course_name.to_string());
        //     };

        //     let mut controller = Controller {
        //         api: mock_api,
        //         exit_fn,
        //         manager: mock_manager,
        //         is_loop: true,
        //         is_boot: true,
        //         show_notif_fn: notif_fn,
        //     };
        //     let result = controller.run_auto_sign_up().await;

        //     // Result needs to be `Ok`
        //     assert!(result.is_ok());
        //     // Notification called with appropriate course names
        //     assert!(notif_fn_called_with[0].contains(&"MATH101".to_string()));
        //     assert!(notif_fn_called_with[1].contains(&"CS102".to_string()));
        // }

        // /// Test successful run with no open exams
        // #[cfg(target_os = "windows")]
        // #[tokio::test]
        // async fn test_run_auto_sign_up_successful_no_exams() {
        //     let mut mock_api = MockApi::new();
        //     let mut mock_manager = MockCredentialManager::default();

        //     // Has valid access_token
        //     let mock_credentials = Credentials {
        //         access_token: Some("valid_token".to_string()),
        //         ..Default::default()
        //     };
        //     mock_manager
        //         .expect_get_valid_credentials()
        //         .return_once(move |_, _, _| Ok(mock_credentials.clone()));

        //     mock_manager
        //         .expect_validate_stored_token()
        //         .return_once(|_, _| Ok(true));

        //     // Returns empty list of couses
        //     let empty_test_list = vec![];
        //     mock_api
        //         .expect_register_for_tests()
        //         .return_once(move |_, _, _, _| Ok(empty_test_list.clone()));

        //     // Dummy exit function
        //     let exit_fn = |_: i32| {};

        //     // Create a spy for the notif_fn
        //     let mut notif_fn_called_with = Vec::new();
        //     let notif_fn = |course_name: &str| {
        //         notif_fn_called_with.push(course_name.to_string());
        //     };

        //     let mut controller = Controller {
        //         api: mock_api,
        //         exit_fn,
        //         manager: mock_manager,
        //         is_loop: true,
        //         is_boot: true,
        //         show_notif_fn: notif_fn,
        //     };
        //     let result = controller.run_auto_sign_up().await;

        //     // Result needs to be `Ok`
        //     assert!(result.is_ok());
        //     // Notification not called
        //     assert!(notif_fn_called_with.is_empty());
        // }

        /// Test when credentials are invalid
        #[tokio::test]
        async fn test_run_auto_sign_up_invalid_credentials() {
            let mock_api = MockApi::new();
            let mut mock_manager = MockCredentialManager::default();

            // `get_valid_credentials()` returns `Err`
            mock_manager
                .expect_get_valid_credentials()
                .return_once(move |_, _, _| {
                    Err(CliError::CredentialError(
                        CredentialError::InvalidCredentials,
                    ))
                });

            let mut controller = Controller {
                api: mock_api,
                exit_fn: |_| {},
                manager: mock_manager,
                is_loop: true,
                is_boot: true,
                show_notif_fn: |_: &str| {},
            };
            let result = controller.run_auto_sign_up().await;

            assert!(result.is_err());
            match result.unwrap_err() {
                CliError::CredentialError(CredentialError::InvalidCredentials) => {}
                _ => panic!("Expected InvalidCredentials error"),
            }
        }
    }

    /// Tests for `run_loop()`
    mod run_loop_tests {
        use crate::api::MockApiTrait;
        use crate::controller::Controller;
        use crate::creds::{Credentials, MockCredentialManagerTrait};
        use crate::models::TestList;
        use crate::{CliError, CredentialError};
        use std::time::Duration;

        /// Tests that `run_loop()` successfully calls `run_auto_sign_up()` at intervals by asserting notifications
        ///
        /// We set run_loop with settings interval_secs = 2 and sleep_interval_secs = 1
        /// The timeout by tokio stops the loop after 3.5 seconds, this results in `run_auto_sign_up()`
        /// being called a total of 3 times (2 on startup and 1 after one sleep iteration)
        #[tokio::test]
        async fn test_run_loop_success() {
            let mut api_mock = MockApiTrait::new();
            let mut manager_mock = MockCredentialManagerTrait::default();
            let mut notifications = Vec::new();

            manager_mock
                .expect_get_valid_credentials()
                .returning(|_, _, _| {
                    Ok(Credentials {
                        access_token: Some("token".to_string()),
                        ..Default::default()
                    })
                });

            manager_mock
                .expect_validate_stored_token()
                .returning(|_, _| Ok(true));

            api_mock
                .expect_register_for_tests()
                .returning(|_, _, _, _| {
                    Ok(vec![TestList {
                        cursus_korte_naam: "Test Exam".to_string(),
                        ..Default::default()
                    }])
                });

            let mut controller = Controller::new(
                api_mock,
                |_| {},
                manager_mock,
                true,
                true,
                |msg: &str| notifications.push(msg.to_string()),
            );

            let timeout_duration = Duration::from_millis(3500);

            let _ = tokio::time::timeout(timeout_duration, async {
                controller.run_loop(2, 1).await;
            })
            .await;

            assert_eq!(notifications.len(), 2);
            assert!(notifications.iter().all(|x| x.contains("Test Exam")));
        }

        /// Tests that `run_loop()` exits when invalid credentials are detected and shows notification
        /// to the user to run `tuenroll start`
        #[tokio::test]
        async fn test_run_loop_invalid_credentials() {
            let mut api_mock = MockApiTrait::new();
            let mut manager_mock = MockCredentialManagerTrait::default();
            let mut notifications = Vec::new();

            manager_mock
                .expect_get_valid_credentials()
                .returning(|_, _, _| {
                    Ok(Credentials {
                        access_token: Some("token".to_string()),
                        ..Default::default()
                    })
                });

            manager_mock
                .expect_validate_stored_token()
                .returning(|_, _| Ok(false));

            api_mock
                .expect_register_for_tests()
                .returning(|_, _, _, _| {
                    Err(CliError::CredentialError(
                        CredentialError::InvalidCredentials,
                    ))
                });

            let mut controller = Controller::new(
                api_mock,
                |_| {},
                manager_mock,
                true,
                true,
                |msg: &str| notifications.push(msg.to_string()),
            );

            let timeout_duration = Duration::from_millis(3500);

            let _ = tokio::time::timeout(timeout_duration, async {
                controller.run_loop(2, 1).await;
            })
            .await;

            assert!(notifications[0]
                .contains(&"Your credentials are invalid. Run tuenroll start again".to_string()));
        }
    }
}
