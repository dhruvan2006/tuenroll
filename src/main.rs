mod api;
use std::io;

#[tokio::main]
async fn main() {
    // When using environment variables
    //let username = std::env::var("username").expect("Username not provided");
    //let password = std::env::var("password").expect("Password not provided");

    // When using cli 
    let (username, password) = get_credentials();

    let access_token = api::get_access_token(username.as_str(), password.as_str()).await;
    println!("{}", access_token.expect("Fetching token failed"));
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