use crate::models::{CourseList, TestList};
use serde_json::Value;
use std::collections::HashMap;

const AUTH_URL: &str = "https://osi-auth-server-prd2.osiris-link.nl/oauth/authorize?response_type=code&client_id=osiris-authorization-server-tudprd&redirect_uri=https://my.tudelft.nl";
const TOKEN_URL: &str = "https://my.tudelft.nl/student/osiris/token";

pub const REGISTERED_COURSE_URL: &str = "https://my.tudelft.nl/student/osiris/student/inschrijvingen/cursussen?toon_historie=N&limit=25";
pub const TEST_COURSE_URL: &str =
    "https://my.tudelft.nl/student/osiris/student/cursussen_voor_toetsinschrijving/";
pub const TEST_REGISTRATION_URL: &str =
    "https://my.tudelft.nl/student/osiris/student/inschrijvingen/toetsen/";

/// Verifies if the user is authenticated by checking for the presence of a redirect URL
/// indicating the need for authentication. If the response does not contain an
/// authentication redirect URL, it is assumed the user is authenticated.
pub async fn is_user_authenticated(
    access_token: &str,
    url: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let response = client.get(url).bearer_auth(access_token).send().await?;
    let response_json: Value = response.json().await?;

    // If "Authenticate-Redirect-Url" exists, the user is not authenticated
    if response_json.get("Authenticate-Redirect-Url").is_some() {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
pub async fn get_access_token(
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Mock implementation for tests
    if username == "valid_user" && password == "valid_pass" {
        Ok("mocked_token".to_string())
    } else {
        Err("Invalid credentials".into())
    }
}

/// Completes the Single Sign-On (SSO) login process for the user and returns a JWT access token.
/// This token can be used for accessing resources at `https://my.tudelft.nl/`.
///
/// Include the HTTP header `Authorization: Bearer <access_token>`
#[cfg(not(test))]
pub async fn get_access_token(
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let (url, body) = initiate_authorization(&client, AUTH_URL).await?;
    let auth_state = get_auth_state(&body);
    let body = submit_login_form(&client, username, password, &url, &auth_state).await?;
    let (form_action, saml_response, relay_state) = extract_saml_response(&body);
    let code = submit_saml_response(
        &client,
        form_action.as_str(),
        saml_response.as_str(),
        relay_state.as_str(),
    )
    .await?;

    let access_token = request_access_token(&client, &code, TOKEN_URL).await?;
    Ok(access_token)
}

async fn initiate_authorization(
    client: &reqwest::Client,
    url: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = client.post(url).send().await?;
    let url = response.url().as_str().to_string();
    let body = response.text().await?;
    Ok((url, body))
}

fn get_auth_state(body: &str) -> String {
    let document = scraper::Html::parse_document(body);
    let form_selector = scraper::Selector::parse("form[name='f']").unwrap();
    let form_element = document.select(&form_selector).next().unwrap();

    let auth_state_selector = scraper::Selector::parse("input[name='AuthState']").unwrap();
    let auth_state_element = form_element.select(&auth_state_selector).next().unwrap();
    auth_state_element
        .value()
        .attr("value")
        .unwrap()
        .to_string()
}

async fn submit_login_form(
    client: &reqwest::Client,
    username: &str,
    password: &str,
    url: &str,
    auth_state: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut form_data = reqwest::multipart::Form::new();
    form_data = form_data.text("username", username.to_string());
    form_data = form_data.text("password", password.to_string());
    form_data = form_data.text("AuthState", auth_state.to_string());

    let response = client.post(url).multipart(form_data).send().await?;
    let body = response.text().await?;

    // Checks whether the username/password was correct by checking if
    // form is in the response HTML
    let document = scraper::Html::parse_document(&body);
    let form_selector = scraper::Selector::parse(
        "form[action='https://osilogin.tudelft.nl/osirissaml/saml2/acs/osiris-student']",
    )
    .expect("Invalid form selector");
    if document.select(&form_selector).next().is_some() {
        return Ok(body);
    }

    Err("Incorrect username or password or form action not found".into())
}

fn extract_saml_response(body: &str) -> (String, String, String) {
    let document = scraper::Html::parse_document(body);

    let form_selector = scraper::Selector::parse("form").unwrap();
    let form_element = document.select(&form_selector).next().unwrap();
    let form_action = form_element.value().attr("action").unwrap().to_string();

    let saml_response = extract_input_value(&form_element, "input[name='SAMLResponse']");
    let relay_state = extract_input_value(&form_element, "input[name='RelayState']");

    (form_action, saml_response, relay_state)
}

fn extract_input_value(element: &scraper::ElementRef, selector_str: &str) -> String {
    let selector = scraper::Selector::parse(selector_str).unwrap();
    let input_element = element.select(&selector).next().unwrap();
    input_element.value().attr("value").unwrap().to_string()
}

async fn submit_saml_response(
    client: &reqwest::Client,
    form_action: &str,
    saml_response: &str,
    relay_state: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut form_data = HashMap::new();
    form_data.insert("SAMLResponse", saml_response);
    form_data.insert("RelayState", relay_state);

    let request = client.post(form_action).form(&form_data);
    let response = request.send().await?;

    let code_url = response.url().as_str();
    let code = code_url
        .split("=")
        .last()
        .expect("Code for authorization missing");

    Ok(code.to_string())
}

async fn request_access_token(
    client: &reqwest::Client,
    code: &str,
    url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut body = HashMap::new();
    body.insert("code", code);
    body.insert("redirect_uri", "");

    let response = client.post(url).json(&body).send().await?;

    let json_response: Value = response.json().await?;
    let access_token = json_response["access_token"]
        .as_str()
        .expect("access_token not found or invalid type")
        .to_string();

    Ok(access_token)
}

/// Gets the courses that the user is currently enrolled in
/// Gets the exams that are available for enrollment based on the courses
/// Signs up to those exams
pub async fn register_for_tests(
    access_token: &str,
    registered_course_url: &str,
    test_course_url: &str,
    test_registration_url: &str,
) -> Result<Vec<TestList>, Box<dyn std::error::Error>> {
    // Gets all the tests for all the courses that the user is currently enrolled in
    let courses = get_course_list(access_token, registered_course_url)
        .await
        .expect("Fetching courses failed");
    let mut test_list: Vec<TestList> = Vec::new();
    for course in courses.items {
        let course_tests =
            get_test_list_for_course(access_token, course.id_cursus, test_course_url).await?;
        if course_tests.is_none() {
            continue;
        }
        test_list.push(course_tests.expect("TestList not found"));
    }

    // Enroll for all the tests found
    let mut enrollments = Vec::new();
    for test in test_list {
        if register_for_test(access_token, &test, test_registration_url).await? {
            enrollments.push(test);
        }
    }

    Ok(enrollments)
}

/// Retrieves the user's registered course list from `course_url` using a JWT `access_token`.
/// Returns a `CourseList` if successful. If the token is invalid or expired,
/// it returns an error with a redirect URL for reauthentication
pub async fn get_course_list(
    access_token: &str,
    course_url: &str,
) -> Result<CourseList, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let response = client
        .get(course_url)
        .bearer_auth(access_token)
        .send()
        .await?;
    let response_text = response.text().await?;
    let response_json: Value = serde_json::from_str(&response_text)?;

    // Handle unauthenticated request
    if let Some(auth_redirect_url) = response_json.get("Authenticate-Redirect-Url") {
        return Err(format!(
            "Unauthenticated: Redirect to {}",
            auth_redirect_url.as_str().unwrap_or("unknown URL")
        )
        .into());
    }

    // TODO: The URL is hardcoded to include max of 25 courses.
    let course_list: CourseList = serde_json::from_value(response_json)?;
    Ok(course_list)
}

/// Retrieves the list of tests availble for registration given the `course_id` using a JWT `access_token`.
/// Returns a `TestList` if successful. If the `course_id` does not have a test open for enrollment
/// the function returns an error
pub async fn get_test_list_for_course(
    access_token: &str,
    course_id: u32,
    url: &str,
) -> Result<Option<TestList>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let test_url = url.to_string() + course_id.to_string().as_str();
    let response = client
        .get(test_url)
        .bearer_auth(access_token)
        .send()
        .await?;
    let response_json: Value = response.json().await?;

    // URL endpoint returns JSON with failure if no tests open for enrollment
    if response_json.get("failure").is_some() {
        return Ok(None);
        //return Err(format!("No test open for enrollment for course_id: {}", course_id).into());
    }

    let test_list: TestList = serde_json::from_value(response_json)?;
    Ok(Some(test_list))
}

/// Registers for the list of test contained in `toetsen`.
/// Returns `true` if registration was successful and `false` if the registration failed.
/// `Err` is returned for any other issue.
// TODO: How to test this method?
pub async fn register_for_test(
    access_token: &str,
    toetsen: &TestList,
    url: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
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

    Err("Unexpected return format".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let response = is_user_authenticated("access_token", &*url).await.unwrap();

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
        let response = is_user_authenticated("access_token", &*url).await.unwrap();

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

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();
        let request_url = format!("{}/oauth/authorize", url);
        let response = initiate_authorization(&client, &request_url).await;

        assert!(response.is_ok());
        let (url, body) = response.unwrap();
        assert!(url.contains("/final-destination"));
        assert!(body.contains("Final destination reached"));

        _mock_redirect.assert();
        _mock_final_destination.assert();
    }

    /// Tests a real OAuth flow by calling the live `/oauth/authorize` endpoint.
    /// Verifies that `initiate_authorization` correctly follows a live 302 redirect and ensures that the response body contains the expected form data and `AuthState` parameter.
    #[tokio::test]
    async fn test_initiate_authorization_live() {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();
        let response = initiate_authorization(&client, AUTH_URL).await;

        assert!(response.is_ok());
        // Url should be of the form https://login.tudelft.nl/sso/module.php/core/loginuserpass.php?AuthState=<auth_state>
        let (url, body) = response.unwrap();
        assert!(url
            .contains("https://login.tudelft.nl/sso/module.php/core/loginuserpass.php?AuthState="));
        assert!(body.contains("<form"));
        assert!(body.contains("AuthState"));
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

        let auth_state = get_auth_state(html);
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

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();
        let request_url = format!("{}/submit_login", url);
        let body = submit_login_form(&client, username, password, &request_url, auth_state)
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

        let (form_action, saml_response, relay_state) = extract_saml_response(html);

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

        let value = extract_input_value(&form_element, "input[name='test']");
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

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();
        let form_action = format!("{}/saml/response", url);
        let saml_response = "dummy_saml_response";
        let relay_state = "dummy_relay_state";

        let result = submit_saml_response(&client, &form_action, saml_response, relay_state).await;

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

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();
        let code = "auth_code_example";
        let request_url = format!("{}/access_token", url);

        let result = request_access_token(&client, code, &request_url).await;

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
        let result = get_course_list("valid_token", course_url).await;

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
        let result = get_course_list("test-access-token", &url).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Redirect to https://auth.url/reauthenticate"));
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
        let result = get_test_list_for_course("valid_token", 1234, &url).await;

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
        let result = get_test_list_for_course("valid_token", 1234, &url).await;

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

        // Mocks for all the get requests of the tests for each course
        let _mock_test_software_quality = server.mock("GET", "/tests/1234")
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

        let _mock_test_algorithm = server.mock("GET", "/tests/12345678")
            .match_header("authorization", "Bearer valid_token")
            .with_status(200)
            .with_body(serde_json::json!({
                "id_cursus": 12345678, "studentnummer": "s1234567", "cursus": "Algorithm Design", "collegejaar": 2024, "cursus_korte_naam": "AD", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
                "toetsen": [
                    {"id_cursus": 12345678, "id_toets_gelegenheid": 12,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                    { "id_cursus": 12345678, "id_toets_gelegenheid": 13, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-12", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
                ]
            }).to_string())
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
        let software_test_registration = server.mock("POST", "/test-reg")
            .match_header("authorization", "Bearer valid_token")
            .match_body(mockito::Matcher::PartialJsonString(serde_json::json!({
                "id_cursus": 1234, "studentnummer": "s1234567", "cursus": "Software Testing", "collegejaar": 2024, "cursus_korte_naam": "ST", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
                "toetsen": [
                    {"id_cursus": 1234, "id_toets_gelegenheid": 69,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                    { "id_cursus": 1234, "id_toets_gelegenheid": 70, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-20", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
                ]
            }).to_string()))
            .with_status(200)
            .with_body(r#"{"statusmeldingen": ""}"#)
            .create();

        let algorithm_test_registration = server.mock("POST", "/test-reg")
            .match_header("authorization", "Bearer valid_token")
            .match_body(mockito::Matcher::PartialJsonString(serde_json::json!({
                "id_cursus": 12345678, "studentnummer": "s1234567", "cursus": "Algorithm Design", "collegejaar": 2024, "cursus_korte_naam": "AD", "opmerking_cursus": "Bring your laptop to all sessions", "punten": 5, "punteneenheid": "ECTS", "coordinerend_onderdeel_oms": "Department of Computer Science", "faculteit_naam": "Faculty of Science", "categorie_omschrijving": "Required Course", "cursustype_omschrijving": "Regular Course", "onderdeel_van": "Bachelor Computer Science",
                "toetsen": [
                    {"id_cursus": 12345678, "id_toets_gelegenheid": 12,"toets": "Final Exam", "toets_omschrijving": "Written examination covering all course material", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 2", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block A", "periode_omschrijving": "Q2", "gelegenheid": 1, "beschikbare_plekken": 150, "toetsdatum": "2024-11-09", "dag": "Monday", "tijd_vanaf": 9.0, "tijd_tm": 12.0, "locatie": "Science Park 904 - H0.08", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] },
                    { "id_cursus": 12345678, "id_toets_gelegenheid": 13, "toets": "Resit Exam", "toets_omschrijving": "Resit examination for those who failed the first attempt", "toetsvorm_omschrijving": "Written Exam", "opmerking_cursus_toets": "No books allowed", "aanvangsblok": "Block 3", "onderwijsvorm": "Lecture", "onderwijsvorm_omschrijving": "Lectures and practical sessions", "blok": "Block B", "periode_omschrijving": "Q3", "gelegenheid": 2, "beschikbare_plekken": 50, "toetsdatum": "2024-12-12", "dag": "Friday", "tijd_vanaf": 13.0, "tijd_tm": 16.0, "locatie": "Science Park 904 - H0.09", "locatie_x": "52.3564", "locatie_y": "4.9565", "eerder_voldoende_behaald": "No", "voorzieningen": [ "Extra time", "Laptop", "Power outlet" ] }
                ]
            }).to_string()))
            .with_status(200)
            .with_body(r#"{"statusmeldingen": ""}"#)
            .create();

        let course_url = &format!("{}/cursussen", server.url());
        let test_url = &format!("{}/tests/", server.url());
        let test_reg_url = &format!("{}/test-reg", server.url());
        let result = register_for_tests("valid_token", &course_url, &test_url, &test_reg_url).await;

        assert!(result.is_ok());
        algorithm_test_registration.assert();
        software_test_registration.assert();
    }
}
