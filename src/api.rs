use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

const AUTH_URL: &str = "https://osi-auth-server-prd2.osiris-link.nl/oauth/authorize?response_type=code&client_id=osiris-authorization-server-tudprd&redirect_uri=https://my.tudelft.nl";
const TOKEN_URL: &str = "https://my.tudelft.nl/student/osiris/token";

pub const REGISTERED_COURSE_URL: &str = "https://my.tudelft.nl/student/osiris/student/inschrijvingen/cursussen?toon_historie=N&limit=25";

#[derive(Deserialize, Debug)]
pub struct CourseList {
    count: u32,
    hasMore: bool,
    items: Vec<Course>,
    limit: u32,
    offset: u32,
}

#[derive(Deserialize, Debug)]
pub struct Course {
    id_cursus: u32,
    cursus: String,
    cursus_korte_naam: String,
}

/// Completes the Single Sign-On (SSO) login process for the user and returns a JWT access token.
/// This token can be used for accessing resources at `https://my.tudelft.nl/`.
/// 
/// Include the HTTP header `Authorization: Bearer <access_token>`
pub async fn get_access_token(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let (url, body) = initiate_authorization(&client, AUTH_URL).await?;
    let auth_state = get_auth_state(&body);
    let body = submit_login_form(&client, username, password, &url, &auth_state).await?;
    let (form_action, saml_response, relay_state) = extract_saml_response(&body);
    let code = submit_saml_response(&client, form_action.as_str(), saml_response.as_str(), relay_state.as_str()).await?;
    
    let access_token = request_access_token(&client, &code, TOKEN_URL).await?;
    Ok(access_token)
}

async fn initiate_authorization(client: &reqwest::Client, url: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = client.post(url).send().await?;
    let url = response.url().as_str().to_string();
    let body = response.text().await?;
    Ok((url, body))
}

fn get_auth_state(body: &str) -> String {
    let document = scraper::Html::parse_document(&body);
    let form_selector = scraper::Selector::parse("form[name='f']").unwrap();
    let form_element = document.select(&form_selector).next().unwrap();

    let auth_state_selector = scraper::Selector::parse("input[name='AuthState']").unwrap();
    let auth_state_element = form_element.select(&auth_state_selector).next().unwrap();
    auth_state_element.value().attr("value").unwrap().to_string()
}

async fn submit_login_form(client: &reqwest::Client, username: &str, password: &str, url: &str, auth_state: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut form_data = reqwest::multipart::Form::new();
    form_data = form_data.text("username", username.to_string());
    form_data = form_data.text("password", password.to_string());
    form_data = form_data.text("AuthState", auth_state.to_string());

    let response = client.post(url).multipart(form_data).send().await?;
    Ok(response.text().await?)
}

fn extract_saml_response(body: &str) -> (String, String, String) {
    let document = scraper::Html::parse_document(&body);

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

async fn submit_saml_response(client: &reqwest::Client, form_action: &str, saml_response: &str, relay_state: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut form_data = HashMap::new();
    form_data.insert("SAMLResponse", saml_response);
    form_data.insert("RelayState", relay_state);

    let request = client.post(form_action).form(&form_data);
    let response = request.send().await?;

    let code_url = response.url().as_str();
    let code = code_url.split("=").last().expect("Code for authorization missing");
    
    Ok(code.to_string())
}

async fn request_access_token(client: &reqwest::Client, code: &str, url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut body = HashMap::new();
    body.insert("code", code);
    body.insert("redirect_uri", "");

    let response = client.post(url).json(&body).send().await?;

    let json_response: Value = response.json().await?;
    let access_token = json_response["access_token"]
        .as_str()
        .ok_or("access_token not found or invalid type")?
        .to_string();

    Ok(access_token)
}

/// Retrieves the user's registered course list from `course_url` using a JWT `access_token`.
/// Returns a `CourseList` if successful. If the token is invalid or expired,
/// it returns an error with a redirect URL for reauthentication
pub async fn get_course_list(access_token: &str, course_url: &str) -> Result<CourseList, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let response = client.get(course_url).bearer_auth(access_token).send().await?;
    let response_text = response.text().await?;
    let response_json: Value = serde_json::from_str(&response_text)?;

    // Handle unauthenticated request
    if let Some(auth_redirect_url) = response_json.get("Authenticate-Redirect-Url") {
        return Err(format!(
            "Unauthenticated: Redirect to {}",
            auth_redirect_url.as_str().unwrap_or("unknown URL")
        ).into());
    }

    // TODO: The URL is hardcoded to include max of 25 courses.
    let course_list: CourseList = serde_json::from_value(response_json)?;
    Ok(course_list)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates an OAuth flow by mocking `/oauth/authorize` to redirect to `/final-destination`.
    /// Verifies that `initiate_authorization` correctly follows a 302 redirect and ensures that the response body matches the body of the redirected URL.
    #[tokio::test]
    async fn test_initiate_authorization_mock() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let redirect_url = format!("{}/final-destination", url);

        let _mock_redirect = server.mock("POST", "/oauth/authorize")
            .with_status(302)
            .with_header("Location", &redirect_url)
            .create();

        let _mock_final_destination = server.mock("GET", "/final-destination")
            .with_status(200)
            .with_body("Final destination reached")
            .create();

        let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
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
        let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
        let response = initiate_authorization(&client, AUTH_URL).await;

        assert!(response.is_ok());
        // Url should be of the form https://login.tudelft.nl/sso/module.php/core/loginuserpass.php?AuthState=<auth_state>
        let (url, body) = response.unwrap();
        assert!(url.contains("https://login.tudelft.nl/sso/module.php/core/loginuserpass.php?AuthState="));
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

        let _mock = server.mock("POST", "/submit_login")
            .with_status(200)
            .with_body("Login successful")
            .create();

        let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
        let request_url = format!("{}/submit_login", url);
        let body = submit_login_form(&client, username, password, &request_url, auth_state).await.expect("Failed to submit login form");

        assert_eq!(body, "Login successful");

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

        let _mock_redirect = server.mock("POST", "/saml/response")
            .with_status(302)
            .with_header("Location", &format!("{}/callback?code=auth_code_example", url))
            .create();

        let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
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

        let _mock = server.mock("POST", "/access_token")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(serde_json::json!({
                "access_token": "example_access_token"
            }).to_string())
            .create();

        let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
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

        let _mock_redirect = server.mock("GET", "/cursussen")
            .with_status(401)
            .with_body(r#"{ "Authenticate-Redirect-Url": "https://auth.url/reauthenticate" }"#)
            .create();
        
        let url = format!("{}/cursussen", server.url());
        let result = get_course_list("test-access-token", &url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Redirect to https://auth.url/reauthenticate"));
    }
}
