use std::collections::HashMap;

const AUTH_URL: &str = "https://osi-auth-server-prd2.osiris-link.nl/oauth/authorize?response_type=code&client_id=osiris-authorization-server-tudprd&redirect_uri=https://my.tudelft.nl";
const TOKEN_URL: &str = "https://my.tudelft.nl/student/osiris/token";

/// Completes the Single Sign-On (SSO) login process for the user and returns a JWT access token.
/// This token can be used for accessing resources at `https://my.tudelft.nl/`.
/// 
/// Include the HTTP header `Authorization: Bearer <access_token>`
pub async fn get_access_token(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let (url, body) = initiate_authorization(&client).await?;
    let auth_state = get_auth_state(&body);
    let body = submit_login_form(&client, username, password, &url, &auth_state).await?;
    let (form_action, saml_response, relay_state) = extract_saml_response(&body);
    let code = submit_saml_response(&client, form_action.as_str(), saml_response.as_str(), relay_state.as_str()).await?;
    
    let access_token = request_access_token(&client, &code).await?;
    Ok(access_token)
}

async fn initiate_authorization(client: &reqwest::Client) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = client.post(AUTH_URL).send().await?;
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

async fn request_access_token(client: &reqwest::Client, code: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut body = HashMap::new();
    body.insert("code", code);
    body.insert("redirect_uri", "");

    let response = client.post(TOKEN_URL).json(&body).send().await?;

    let json_response: serde_json::Value = response.json().await?;
    let access_token = json_response["access_token"]
        .as_str()
        .ok_or("access_token not found or invalid type")?
        .to_string();

    Ok(access_token)
}


#[cfg(test)]
mod tests {
    use super::*;

    // Tests for get_auth_state
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

    // Tests for extract_saml_response
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

    // Tests for extract_input_value
    #[test]
    fn test_extract_input_value() {
        let html = r#"<form><input name="test" value="test-value"/></form>"#;
        let document = scraper::Html::parse_document(html);
        let form_selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&form_selector).next().unwrap();
        
        let value = extract_input_value(&form_element, "input[name='test']");
        assert_eq!(value, "test-value");
    }
}
