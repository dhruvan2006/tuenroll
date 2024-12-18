use crate::models::{CourseList, TestList};
use crate::{ApiError, CliError, CredentialError};
use async_trait::async_trait;
use mockall::automock;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;

const AUTH_URL: &str = "https://osi-auth-server-prd2.osiris-link.nl/oauth/authorize?response_type=code&client_id=osiris-authorization-server-tudprd&redirect_uri=https://my.tudelft.nl";
const TOKEN_URL: &str = "https://my.tudelft.nl/student/osiris/token";

pub const BASE_URL: &str = "https://my.tudelft.nl";
pub const REGISTERED_COURSE_URL: &str = "https://my.tudelft.nl/student/osiris/student/inschrijvingen/cursussen?toon_historie=N&limit=25";
pub const TEST_COURSE_URL: &str =
    "https://my.tudelft.nl/student/osiris/student/cursussen_voor_toetsinschrijving/";
pub const TEST_REGISTRATION_URL: &str =
    "https://my.tudelft.nl/student/osiris/student/inschrijvingen/toetsen/";

#[automock]
#[async_trait]
pub trait ApiTrait {
    async fn is_user_authenticated(&self, access_token: &str, url: &str) -> Result<bool, ApiError>;
    async fn get_access_token(&self, username: &str, password: &str) -> Result<String, CliError>;
    async fn register_for_tests(
        &self,
        access_token: &str,
        registered_course_url: &str,
        test_course_url: &str,
        test_registration_url: &str,
    ) -> Result<Vec<TestList>, CliError>;
}

pub struct Api {
    client: Client,
}

#[async_trait]
impl ApiTrait for Api {
    async fn is_user_authenticated(&self, access_token: &str, url: &str) -> Result<bool, ApiError> {
        self.is_user_authenticated(access_token, url).await
    }

    async fn get_access_token(&self, username: &str, password: &str) -> Result<String, CliError> {
        self.get_access_token(username, password).await
    }

    async fn register_for_tests(
        &self,
        access_token: &str,
        registered_course_url: &str,
        test_course_url: &str,
        test_registration_url: &str,
    ) -> Result<Vec<TestList>, CliError> {
        self.register_for_tests(
            access_token,
            registered_course_url,
            test_course_url,
            test_registration_url,
        )
        .await
    }
}

impl Api {
    /// Initializes a new instance of `Api` with a `reqwest::Client`` that persists cookies
    pub fn new() -> Result<Self, ApiError> {
        let client = Client::builder().cookie_store(true).build()?;

        Ok(Api { client })
    }

    /// Verifies if the user is authenticated by checking for the presence of a redirect URL
    /// indicating the need for authentication. If the response does not contain an
    /// authentication redirect URL, it is assumed the user is authenticated.
    pub async fn is_user_authenticated(
        &self,
        access_token: &str,
        url: &str,
    ) -> Result<bool, ApiError> {
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let response_json: Value = response.json().await?;

        // If "Authenticate-Redirect-Url" exists, the user is not authenticated
        if response_json.get("Authenticate-Redirect-Url").is_some() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Completes the Single Sign-On (SSO) login process for the user and returns a JWT access token.
    /// This token can be used for accessing resources at `https://my.tudelft.nl/`.
    ///
    /// Include the HTTP header `Authorization: Bearer <access_token>`
    pub async fn get_access_token(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, CliError> {
        let (url, body) = self.initiate_authorization(AUTH_URL).await?;
        let auth_state = Self::get_auth_state(&body)?;
        let body = self
            .submit_login_form(username, password, &url, &auth_state)
            .await?;
        let (form_action, saml_response, relay_state) = Self::extract_saml_response(&body)?;
        let code = self
            .submit_saml_response(
                form_action.as_str(),
                saml_response.as_str(),
                relay_state.as_str(),
            )
            .await?;

        let access_token = self.request_access_token(&code, TOKEN_URL).await?;
        Ok(access_token)
    }

    async fn initiate_authorization(&self, url: &str) -> Result<(String, String), ApiError> {
        let response = self.client.post(url).send().await?;
        let url = response.url().as_str().to_string();
        let body = response.text().await?;
        Ok((url, body))
    }

    fn get_auth_state(body: &str) -> Result<String, CliError> {
        let document = scraper::Html::parse_document(body);

        let form_selector = scraper::Selector::parse("form[name='f']")
            .map_err(|e| ApiError::InvalidResponse(format!("Form selector parse error: {}", e)))?;

        let form_element = document
            .select(&form_selector)
            .next()
            .ok_or_else(|| CredentialError::InvalidCredentials)?;

        let auth_state_selector =
            scraper::Selector::parse("input[name='AuthState']").map_err(|e| {
                ApiError::InvalidResponse(format!("AuthState selector parse error: {}", e))
            })?;

        let auth_state_element = form_element
            .select(&auth_state_selector)
            .next()
            .ok_or_else(|| ApiError::InvalidResponse("AuthState input not found".to_string()))?;

        auth_state_element
            .value()
            .attr("value")
            .map(|v| v.to_string())
            .ok_or_else(|| {
                CliError::from(ApiError::InvalidResponse(
                    "AuthState value not found".to_string(),
                ))
            })
    }

    async fn submit_login_form(
        &self,
        username: &str,
        password: &str,
        url: &str,
        auth_state: &str,
    ) -> Result<String, CliError> {
        let mut form_data = reqwest::multipart::Form::new();
        form_data = form_data.text("username", username.to_string());
        form_data = form_data.text("password", password.to_string());
        form_data = form_data.text("AuthState", auth_state.to_string());

        let response = self
            .client
            .post(url)
            .multipart(form_data)
            .send()
            .await
            .map_err(ApiError::NetworkError)?;
        let body = response.text().await.map_err(ApiError::NetworkError)?;

        // Checks whether the username/password was correct by checking if
        // form is in the response HTML
        let document = scraper::Html::parse_document(&body);
        let form_selector = scraper::Selector::parse("form")
            .map_err(|e| ApiError::InvalidResponse(format!("Form selector parse error: {}", e)))?;
        if document.select(&form_selector).next().is_some() {
            return Ok(body);
        }

        Err(CliError::from(CredentialError::InvalidCredentials))
    }

    fn extract_saml_response(body: &str) -> Result<(String, String, String), CliError> {
        let document = scraper::Html::parse_document(body);

        let form_selector = scraper::Selector::parse("form")
            .map_err(|e| ApiError::InvalidResponse(format!("Form selector parse error: {}", e)))?;

        let form_element = document
            .select(&form_selector)
            .next()
            .ok_or_else(|| ApiError::InvalidResponse("Form element not found".to_string()))?;

        let form_action = form_element
            .value()
            .attr("action")
            .ok_or_else(|| ApiError::InvalidResponse("Form action not found".to_string()))?
            .to_string();

        let saml_response = Self::extract_input_value(&form_element, "input[name='SAMLResponse']")?;
        let relay_state = Self::extract_input_value(&form_element, "input[name='RelayState']")?;

        Ok((form_action, saml_response, relay_state))
    }

    fn extract_input_value(
        element: &scraper::ElementRef,
        selector_str: &str,
    ) -> Result<String, CliError> {
        let selector = scraper::Selector::parse(selector_str)
            .map_err(|e| ApiError::InvalidResponse(format!("Selector parse error: {}", e)))?;

        let input_element = element
            .select(&selector)
            .next()
            .ok_or_else(|| CredentialError::InvalidCredentials)?;

        input_element
            .value()
            .attr("value")
            .map(|v| v.to_string())
            .ok_or_else(|| {
                CliError::from(ApiError::InvalidResponse(
                    "Attribute 'value' not found".to_string(),
                ))
            })
    }

    async fn submit_saml_response(
        &self,
        form_action: &str,
        saml_response: &str,
        relay_state: &str,
    ) -> Result<String, ApiError> {
        let mut form_data = HashMap::new();
        form_data.insert("SAMLResponse", saml_response);
        form_data.insert("RelayState", relay_state);

        let request = self.client.post(form_action).form(&form_data);
        let response = request.send().await?;

        let code_url = response.url().as_str();
        let code = code_url
            .split('=')
            .last()
            .ok_or_else(|| ApiError::InvalidResponse("Authorization code missing".to_string()))?;

        Ok(code.to_string())
    }

    async fn request_access_token(&self, code: &str, url: &str) -> Result<String, ApiError> {
        let mut body = HashMap::new();
        body.insert("code", code);
        body.insert("redirect_uri", "");

        let response = self.client.post(url).json(&body).send().await?;

        let json_response: Value = response.json().await?;
        let access_token = json_response["access_token"]
            .as_str()
            .ok_or_else(|| ApiError::InvalidResponse("Authorization code missing".to_string()))?
            .to_string();

        Ok(access_token)
    }

    /// Gets the courses that the user is currently enrolled in
    /// Gets the exams that are available for enrollment based on the courses
    /// Signs up to those exams
    pub async fn register_for_tests(
        &self,
        access_token: &str,
        registered_course_url: &str,
        test_course_url: &str,
        test_registration_url: &str,
    ) -> Result<Vec<TestList>, CliError> {
        // Gets all the tests for all the courses that the user is currently enrolled in
        let courses = self
            .get_course_list(access_token, registered_course_url)
            .await?; //Fetching courses failed

        let mut test_list: Vec<TestList> = Vec::new();
        for course in courses.items {
            let course_tests = self
                .get_test_list_for_course(access_token, course.id_cursus, test_course_url)
                .await?;
            if course_tests.is_none() {
                continue;
            }
            test_list.push(
                course_tests
                    .ok_or_else(|| ApiError::InvalidResponse("TestList not found".to_string()))?,
            );
        }

        // Enroll for all the tests found
        let mut enrollments = Vec::new();
        for test in test_list {
            if self
                .register_for_test(access_token, &test, test_registration_url)
                .await?
            {
                enrollments.push(test);
            }
        }

        Ok(enrollments)
    }

    /// Retrieves the user's registered course list from `course_url` using a JWT `access_token`.
    /// Returns a `CourseList` if successful. If the token is invalid or expired,
    /// it returns an error with a redirect URL for reauthentication
    pub async fn get_course_list(
        &self,
        access_token: &str,
        course_url: &str,
    ) -> Result<CourseList, CliError> {
        let response = self
            .client
            .get(course_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(ApiError::NetworkError)?;
        let response_text = response.text().await.map_err(ApiError::NetworkError)?;
        let response_json: Value =
            serde_json::from_str(&response_text).map_err(ApiError::JsonDecodeError)?;

        // Handle unauthenticated request
        if response_json.get("Authenticate-Redirect-Url").is_some() {
            return Err(CredentialError::InvalidCredentials)?;
        }

        let course_list: CourseList =
            serde_json::from_value(response_json).map_err(ApiError::JsonDecodeError)?;
        Ok(course_list)
    }

    /// Retrieves the list of tests availble for registration given the `course_id` using a JWT `access_token`.
    /// Returns a `TestList` if successful. If the `course_id` does not have a test open for enrollment
    /// the function returns an error
    pub async fn get_test_list_for_course(
        &self,
        access_token: &str,
        course_id: u32,
        url: &str,
    ) -> Result<Option<TestList>, ApiError> {
        let test_url = url.to_string() + course_id.to_string().as_str();
        let response = self
            .client
            .get(test_url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let response_json: Value = response.json().await?;

        if response_json.get("failure").is_some() {
            return Ok(None);
        }

        let test_list: TestList = serde_json::from_value(response_json)?;
        Ok(Some(test_list))
    }

    /// Registers for the list of test contained in `toetsen`.
    /// Returns `true` if registration was successful and `false` if the registration failed.
    /// `Err` is returned for any other issue.
    // TODO: How to test this method?
    pub async fn register_for_test(
        &self,
        access_token: &str,
        toetsen: &TestList,
        url: &str,
    ) -> Result<bool, ApiError> {
        let response = self
            .client
            .post(url)
            .bearer_auth(access_token)
            .json(toetsen)
            .send()
            .await?;
        let json_response: Value = response.json().await?;

        if let Some(statusmeldingen) = json_response.get("statusmeldingen") {
            // If statusmeldingen is empty we were successful, else it reported failure
            return if statusmeldingen
                .as_array()
                .map_or(false, |arr| arr.is_empty())
            {
                Ok(true)
            } else {
                Ok(false)
            };
        }

        Err(ApiError::InvalidResponse(
            "Unexpected return format".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliError;

    #[tokio::test]
    async fn test_is_user_authenticated_mock_authenticated() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header("Authorization", "Bearer access_token")
            .with_body(
                serde_json::json!({
                    "random": "json test body"
                })
                .to_string(),
            )
            .create();

        let url = format!("{}/test", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let response = api
            .is_user_authenticated("access_token", &*url)
            .await
            .unwrap();

        assert!(response);
        mock.assert();
    }

    #[tokio::test]
    async fn test_is_user_authenticated_mock_unauthenticated() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header("Authorization", "Bearer access_token")
            .with_body(
                serde_json::json!({
                    "Authenticate-Redirect-Url": "doesn't matter"
                })
                .to_string(),
            )
            .create();

        let url = format!("{}/test", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let response = api
            .is_user_authenticated("access_token", &*url)
            .await
            .unwrap();

        assert!(!response);
        mock.assert();
    }

    /// Simulates an OAuth flow by mocking `/oauth/authorize` to redirect to `/final-destination`.
    /// Verifies that `initiate_authorization` correctly follows a 302 redirect and ensures that the response body matches the body of the redirected URL.
    #[tokio::test]
    async fn test_initiate_authorization_mock() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let redirect_url = format!("{}/final-destination", url);

        let _mock_redirect = server
            .mock("POST", "/oauth/authorize")
            .with_status(302)
            .with_header("Location", &redirect_url)
            .create();

        let _mock_final_destination = server
            .mock("GET", "/final-destination")
            .with_status(200)
            .with_body("Final destination reached")
            .create();

        let request_url = format!("{}/oauth/authorize", url);
        let api = Api::new().expect("Failed to start reqwest Client");
        let response = api.initiate_authorization(&request_url).await;

        assert!(response.is_ok());
        let (url, body) = response.unwrap();
        assert!(url.contains("/final-destination"));
        assert!(body.contains("Final destination reached"));

        _mock_redirect.assert();
        _mock_final_destination.assert();
    }

    #[test]
    fn test_get_auth_state() {
        let html = r#"
            <form name="f">
                <input type="hidden" name="AuthState" value="test-auth-state-123"/>
                <input type="text" name="username"/>
                <input type="password" name="password"/>
            </form>
        "#;

        let auth_state = Api::get_auth_state(html).unwrap();
        assert_eq!(auth_state, "test-auth-state-123");
    }

    /// Simulates submitting a login form using mock server to test `submit_login_form` function.
    /// Verifies that the response body matches the expected message from the server.
    #[tokio::test]
    async fn test_submit_login_form_mock() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let username = "testuser";
        let password = "testpassword";
        let auth_state = "test_auth_state";

        let original_body = "<form action='https://osilogin.tudelft.nl/osirissaml/saml2/acs/osiris-student'></form>";

        let _mock = server
            .mock("POST", "/submit_login")
            .with_status(200)
            .with_body(original_body)
            .create();

        let request_url = format!("{}/submit_login", url);
        let api = Api::new().expect("Failed to start reqwest Client");
        let body = api
            .submit_login_form(username, password, &request_url, auth_state)
            .await
            .expect("Failed to submit login form");

        assert_eq!(body, original_body);

        _mock.assert();
    }

    #[test]
    fn test_extract_saml_response() {
        let html = r#"
            <form action="https://example.com/saml">
                <input type="hidden" name="SAMLResponse" value="encrypted-saml-data"/>
                <input type="hidden" name="RelayState" value="state-123"/>
            </form>
        "#;

        let (form_action, saml_response, relay_state) = Api::extract_saml_response(html).unwrap();

        assert_eq!(form_action, "https://example.com/saml");
        assert_eq!(saml_response, "encrypted-saml-data");
        assert_eq!(relay_state, "state-123");
    }

    #[test]
    fn test_extract_input_value() {
        let html = r#"<form><input name="test" value="test-value"/></form>"#;
        let document = scraper::Html::parse_document(html);
        let form_selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&form_selector).next().unwrap();

        let value = Api::extract_input_value(&form_element, "input[name='test']").unwrap();
        assert_eq!(value, "test-value");
    }

    /// Tests `extract_input_value` by mocking a POST request to simulate submitting a SAML response.
    /// The mock server returns a URL with a code query parameter after form submission.
    #[tokio::test]
    async fn test_submit_saml_response_mock() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let _mock_redirect = server
            .mock("POST", "/saml/response")
            .with_status(302)
            .with_header(
                "Location",
                &format!("{}/callback?code=auth_code_example", url),
            )
            .create();

        let form_action = format!("{}/saml/response", url);
        let saml_response = "dummy_saml_response";
        let relay_state = "dummy_relay_state";

        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api
            .submit_saml_response(&form_action, saml_response, relay_state)
            .await;

        assert!(result.is_ok());
        let code = result.unwrap();
        assert_eq!(code, "auth_code_example");

        _mock_redirect.assert();
    }

    /// Tests `request_access_token` by mocking a POST request to simulate submitting an `access_token` to the server
    /// The mock server returns a access_token in JSON format.
    #[tokio::test]
    async fn test_request_access_token_mock() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let _mock = server
            .mock("POST", "/access_token")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "example_access_token"
                })
                .to_string(),
            )
            .create();

        let code = "auth_code_example";
        let request_url = format!("{}/access_token", url);

        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api.request_access_token(code, &request_url).await;

        assert!(result.is_ok());
        let access_token = result.unwrap();
        assert_eq!(access_token, "example_access_token");

        _mock.assert();
    }

    /// Tests `get_course_list` by simulating a request to retrieve the user's registered course list.
    /// Ensures the function correctly handles a successful response with valid course data.
    #[tokio::test]
    async fn test_get_course_list_mock_success() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server.mock("GET", "/cursussen")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "items": [
                        {"id_cursus": 12345678, "cursus": "CSE2310", "cursus_korte_naam": "Algorithm Design"},
                        {"id_cursus": 99999999, "cursus": "CSE1000", "cursus_korte_naam": "Software Project"}
                    ],
                    "hasMore": false,
                    "limit": 25,
                    "offset": 0,
                    "count": 1
                }).to_string(),
            )
            .create();

        let course_url = &format!("{}/cursussen", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api.get_course_list("valid_token", course_url).await;

        assert!(result.is_ok());
        let course_list = result.unwrap();
        assert_eq!(course_list.items.len(), 2);
        assert_eq!(course_list.items[0].id_cursus, 12345678);
        assert_eq!(course_list.items[0].cursus, "CSE2310");
        assert_eq!(course_list.items[0].cursus_korte_naam, "Algorithm Design");
        assert_eq!(course_list.items[1].id_cursus, 99999999);
        assert_eq!(course_list.items[1].cursus, "CSE1000");
        assert_eq!(course_list.items[1].cursus_korte_naam, "Software Project");
    }

    /// Tests `get_course_list` by simulating a request to retrieve the user's registered course list.
    /// Ensures the function correctly handles an authentication error.
    #[tokio::test]
    async fn test_get_course_list_mock_error() {
        let mut server = mockito::Server::new_async().await;

        let _mock_redirect = server
            .mock("GET", "/cursussen")
            .with_status(401)
            .with_body(r#"{ "Authenticate-Redirect-Url": "https://auth.url/reauthenticate" }"#)
            .create();

        let url = format!("{}/cursussen", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api.get_course_list("test-access-token", &url).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::CredentialError(CredentialError::InvalidCredentials) => {}
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    /// Tests `get_test_list_for_course` by simulating a successful request to retrieve tests available
    /// for registration. Ensures the function parses and returns the expected `TestList`.
    #[tokio::test]
    async fn test_get_list_for_course_mock_success() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server.mock("GET", "/tests/1234")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(serde_json::json!({
                "id_cursus": 1234, "studentnummer": "s1234567", "cursus": "Software Testing", "collegejaar": 2024, "cursus_korte_naam": "ST", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
                "toetsen": [
                    {"id_cursus": 1234, "id_toets_gelegenheid": 69,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                    { "id_cursus": 1234, "id_toets_gelegenheid": 70, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-20", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
                ]
            }).to_string())
            .create();

        let url = format!("{}/tests/", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api
            .get_test_list_for_course("valid_token", 1234, &url)
            .await;

        assert!(result.is_ok());
        let test_list = result.unwrap().unwrap();

        // Verify course details
        assert_eq!(test_list.id_cursus, 1234);
        assert_eq!(test_list.cursus, "Software Testing");
        assert_eq!(test_list.cursus_korte_naam, "ST");

        // Verify test details
        assert_eq!(test_list.toetsen.len(), 2);

        let first_test = &test_list.toetsen[0];
        assert_eq!(first_test.id_toets_gelegenheid, 69);
        assert_eq!(first_test.toets, "Final Exam");
        assert_eq!(first_test.gelegenheid, 1);

        let second_test = &test_list.toetsen[1];
        assert_eq!(second_test.id_toets_gelegenheid, 70);
        assert_eq!(second_test.toets, "Resit Exam");
        assert_eq!(second_test.gelegenheid, 2);
    }

    /// Tests `get_test_list_for_course` by simulating a request where no tests are available for enrollment.
    /// Ensures the function returns an error when `failure` is present in the response JSON.
    #[tokio::test]
    async fn test_get_list_for_course_mock_failure() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server.mock("GET", "/tests/1234")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(serde_json::json!({
                "result": "FAILED",
                "failure": {
                    "message": "Er is een fout opgetreden tijdens het aanroepen van de OSIRIS database",
                    "code": 404,
                    "detail": ""
                }
            }).to_string())
            .create();

        let url = format!("{}/tests/", server.url());
        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api
            .get_test_list_for_course("valid_token", 1234, &url)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_register_for_tests_mock() {
        let mut server = mockito::Server::new_async().await;

        // Mock all the courses
        let _mock_courses = server.mock("GET", "/cursussen")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "items": [
                        {"id_cursus": 12345678, "cursus": "CSE2310", "cursus_korte_naam": "Algorithm Design"},
                        {"id_cursus": 99999999, "cursus": "CSE1000", "cursus_korte_naam": "Software Project"},
                        {"id_cursus": 1234, "cursus": "CSE1110", "cursus_korte_naam": "Software Quality and Testing"}
                    ],
                    "hasMore": false,
                    "limit": 25,
                    "offset": 0,
                    "count": 1
                }).to_string()
            )
            .create();

        let test_1234 = serde_json::json!({
            "id_cursus": 1234, "studentnummer": "s1234567", "cursus": "Software Testing", "collegejaar": 2024, "cursus_korte_naam": "ST", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
            "toetsen": [
                {"id_cursus": 1234, "id_toets_gelegenheid": 69,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                { "id_cursus": 1234, "id_toets_gelegenheid": 70, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-20", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
            ]
        });

        let test_12345678 = serde_json::json!({
            "id_cursus": 12345678, "studentnummer": "s1234567", "cursus": "Algorithm Design", "collegejaar": 2024, "cursus_korte_naam": "AD", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
            "toetsen": [
                {"id_cursus": 12345678, "id_toets_gelegenheid": 12,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                { "id_cursus": 12345678, "id_toets_gelegenheid": 13, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-12", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
            ]
        });

        // Mocks for all the get requests of the tests for each course
        let _mock_test_software_quality = server
            .mock("GET", "/tests/1234")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(test_1234.to_string())
            .create();

        let _mock_test_algorithm = server
            .mock("GET", "/tests/12345678")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(test_12345678.to_string())
            .create();

        let _mock_test_software_project = server
            .mock("GET", "/tests/99999999")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "failure": "some"
                })
                .to_string(),
            )
            .create();

        // Mocks for the registration post requests
        let software_test_registration = server
            .mock("POST", "/test-reg")
            .match_header("authorization", "Bearer valid_token")
            .match_body(mockito::Matcher::PartialJsonString(test_1234.to_string()))
            .with_status(200)
            .with_body(r#"{"statusmeldingen": []}"#)
            .create();

        let algorithm_test_registration = server
            .mock("POST", "/test-reg")
            .match_header("authorization", "Bearer valid_token")
            .match_body(mockito::Matcher::PartialJsonString(
                test_12345678.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"statusmeldingen": []}"#)
            .create();

        let course_url = &format!("{}/cursussen", server.url());
        let test_url = &format!("{}/tests/", server.url());
        let test_reg_url = &format!("{}/test-reg", server.url());

        let expected_tests: Vec<TestList> = vec![
            serde_json::from_value(test_12345678).expect("Conversion failed"),
            serde_json::from_value(test_1234).expect("Conversion failed"),
        ];

        let api = Api::new().expect("Failed to start reqwest Client");
        let result = api
            .register_for_tests("valid_token", &course_url, &test_url, &test_reg_url)
            .await;

        assert!(result.is_ok());

        let result = result.unwrap();

        assert_eq!(expected_tests, result);

        algorithm_test_registration.assert();
        software_test_registration.assert();
    }
}
