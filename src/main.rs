mod api;

#[tokio::main]
async fn main() {
    let username = std::env::var("username").expect("Username not provided");
    let password = std::env::var("password").expect("Password not provided");
    let access_token = api::get_access_token(username.as_str(), password.as_str()).await;
    println!("{}", access_token.expect("Fetching token failed"));
}
