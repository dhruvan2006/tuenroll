mod api;
mod models;
use std::io;

#[tokio::main]
async fn main() {
    // When using environment variables
    //let username = std::env::var("username").expect("Username not provided");
    //let password = std::env::var("password").expect("Password not provided");

    // When using cli 
    let (username, password) = get_credentials();
  
    let access_token = api::get_access_token(username.as_str(), password.as_str()).await.expect("Fetching access token failed");
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



fn get_credentials() -> (String, String) {
    let mut username = String::new();
    let mut password = String::new();

    println!("Input username");
    io::stdin().read_line(&mut username).expect("Couldn't read username");

    println!("Input password");
    io::stdin().read_line(&mut password).expect("Couldn't read password");

    let username = username.trim_end().to_string();
    let password = password.trim_end().to_string();

    return (username, password);
}