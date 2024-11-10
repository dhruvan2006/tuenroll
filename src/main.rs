mod api;
mod models;
use std::io;
use std::io::Write;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

// TODO: Give a finalized name for the directory
const CONFIG_DIR: &str = ".my_cli_app";
const CONFIG_FILE: &str = "config.json";

#[tokio::main]
async fn main() {
    let credentials = get_credentials();
  
    let access_token = api::get_access_token(&credentials.username.as_str(), &credentials.password.as_str()).await.expect("Fetching access token failed");
    println!("Access token: {}", access_token);

    let courses = api::get_course_list(&access_token, api::REGISTERED_COURSE_URL).await.expect("Fetching courses failed");
    println!("Courses: {:?}", courses);

    let tests = api::get_test_list_for_course(&access_token, 116283, api::TEST_COURSE_URL).await.expect("Fetching tests failed");
    println!("Tests: {:?}", tests);

    // let registration_result = api::register_for_test(&access_token, &tests, api::TEST_REGISTRATION_URL).await;
    //
    // match registration_result {
    //     Ok(true) => println!("Successfully registered for the test."),
    //     Ok(false) => println!("Test registrdation encountered issues."),
    //     Err(e) => println!("Failed to register for the test: {}", e),
    // }
}

/// Returns the path to the user's home hidden directory+`config_dir`+`config_file`
fn get_config_path(config_dir: &str, config_file: &str) -> std::path::PathBuf {
    if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(config_dir).join(config_file)
    } else {
        // TODO: Better error handling
        panic!("Could not find home directory.");
    }
}

/// Fetches the user's credentials. If the credentials are already stored in the config file,
/// they are read and returned. If not, the user is prompted to input them, which are then saved
/// to the config file for future use.
fn get_credentials() -> Credentials {
    let config_path = get_config_path(CONFIG_DIR, CONFIG_FILE);

    if let Ok(data) = std::fs::read_to_string(&config_path) {
        if let Ok(credentials) = serde_json::from_str::<Credentials>(&data) {
            return credentials;
        }
    }

    let mut username = String::new();

    print!("Input username: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut username).expect("Couldn't read username");

    print!("Input password: ");
    let _ = io::stdout().flush();
    let password = rpassword::read_password().expect("Failed to read password");

    let credentials = Credentials {
        username: username.trim().to_string(),
        password: password.trim().to_string(),
    };

    std::fs::create_dir_all(config_path.parent().expect("Failed to get parent directory"))
        .expect("Failed to create config directory");

    let serialized = serde_json::to_string(&credentials).expect("Failed to serialize credentials");
    std::fs::write(config_path, serialized).expect("Failed to save credentials");

    credentials
}