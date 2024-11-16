mod api;
mod models;
use std::{env, io};
use std::io::Write;
use serde::{Deserialize, Serialize};
use clap::{Parser, Subcommand};
use std::{thread, time, process::Command};
use log::{info, error, warn};
use simplelog::*;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use notify_rust::Notification;

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: Option<String>,
    password: Option<String>,
    access_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PID {
    pid: Option<u32>
}

#[derive(Parser)]
#[command(name = "TUEnroll CLI", version, about = "Automate your TU Delft exam registrations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts a periodic background test checking process.
    Start {
        /// Interval in hours for periodic checking
        #[arg(short, long, default_value_t = 24)]
        interval: u32,
    },
    /// Stops any running background test checking process.
    Stop,
    /// Runs the check process one time and displays results.
    Run,
    /// Change username and password
    Change,
    /// Delete any saved credentials
    Delete,
}

const CONFIG_DIR: &str = ".tuenroll";
const CONFIG_FILE: &str = "config.json";
const PID_FILE: &str = "process.json";
const LOG_FILE: &str = "tuenroll.log";

#[tokio::main]
async fn main() {
    set_up_logging();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Run => {
            info!("Starting the 'Run' command execution.");
            match run_auto_sign_up(false).await {
                Ok(()) => println!("{}", "Success: Exam check ran.".green().bold()),
                Err(()) => println!("{}", "Failure: A network error occured".red().bold())
            }
            
        },
        Commands::Start { interval } => {
            // WARNING: Do not have any print statements or the the command and process will stop working detached
            if env::var("DAEMONIZED").err().is_some() {
                //  Check that no other process is running
                if process_is_running() {
                    println!("Another process is already running");
                    return;
                }
                info!("Spawning daemon process with interval: {}", interval);
                let child = Command::new(env::current_exe().unwrap())
                    .args(&["start", format!("--interval={}", interval).as_str()])
                    .env("DAEMONIZED", "1")
                    .spawn()
                    .unwrap();
                store_pid(Some(child.id()));
                //println!("{}", "Success: Service started.".green().bold());
                info!("Daemon process started with PID: {}", child.id());
                return
            }
            else {

                run_loop(interval).await;
            }
        },
        Commands::Stop => {
            info!("Stopping the cli.");
            let stopped_process = stop_program();
            if stopped_process.is_none() {
                eprintln!("{}", "Error: No running service to stop.".red());
            }
            else {
                println!("{}", "Background service has been successfully stopped".green().bold());
            }
        },
        Commands::Change => {
            info!("Changing credentials.");
            match change_credentials(&get_config_path(CONFIG_DIR, CONFIG_FILE)).await {
                Ok(_) => println!("{}", "Success: Credentials changed!".green().bold()),
                Err(_) => println!("{}", "Failed: A network problem occured.".red().bold())
            }
            
        }
        Commands::Delete => {
            info!("Deleting credentials.");
            delete_credentials(&get_config_path(CONFIG_DIR, CONFIG_FILE));
            println!("{}", "Success: Credentials deleted!".green().bold());
        }
    }
}

async fn change_credentials(config_path: &std::path::PathBuf) -> Result<Credentials, Box<dyn std::error::Error>> {
    delete_credentials(&config_path);
    return get_valid_credentials(&config_path).await;
}

fn delete_credentials(config_path: &std::path::Path) {
    let creds = Credentials {
        username: None,
        password: None,
        access_token: None,
    };
    save_credentials(&creds, &config_path);
}

fn set_up_logging() {
    let log_path = get_config_path(CONFIG_DIR, LOG_FILE);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create log directory");
    }
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(log_path).unwrap();

    CombinedLogger::init(vec![
        // TermLogger::new(LevelFilter::Info, Config::default(), TerminalMode::Mixed, ColorChoice::Always),
        WriteLogger::new(LevelFilter::Info, Config::default(), log_file),
    ]).expect("Failed to initialize logger");

    info!("Initialized the logger");
}

async fn run_loop(interval: &u32) {
    loop {
        let duration = time::Duration::from_secs((interval*3600).into());
        thread::sleep(duration);
    }
}

fn get_stored_pid() -> Option<u32> {
    if let Ok(pid) = std::fs::read_to_string(get_config_path(CONFIG_DIR, PID_FILE)) {
        if let Ok(pid) = serde_json::from_str::<PID>(&pid) {
            return pid.pid;
        }
    }
    return None;
}


fn stop_program() -> Option<u32> {
    let pid = get_stored_pid();
    if pid.is_none() {return None};
    let pid = pid.unwrap();

    info!("Attempting to stop the process with PID: {}", pid);

    #[cfg(target_os = "windows")]
    let kill = Command::new("taskkill").args(&["/PID", &pid.to_string(), "/F"]).spawn();

    #[cfg(not(target_os = "windows"))]
    let kill = Command::new("kill").arg(pid.to_string()).spawn();

    if let Err(e) = kill {
        error!("Failed to stop process with PID {}: {}", pid, e);
        return None;
    }

    info!("Successfully stopped the process with PID: {}", pid);
    store_pid(None);
    Some(pid)
}

fn process_is_running() -> bool {
    let stored_pid = get_stored_pid();
    if stored_pid.is_none() {return false};
    let process = Command::new("ps").args(["-p", stored_pid.unwrap().to_string().as_str()]).output().expect("Error occured when running ps -p $PID");
    if process.status.success() {
        info!("Process with PID {} is running.", stored_pid.unwrap());
        return true;
    }
    else {
        warn!("Process with PID {} is not running. Cleaning up PID store.", stored_pid.unwrap());
        store_pid(None);
    }
    false
}


/// Runs the auto signup fully o nce
/// Gets the credentials, the access token 
/// Automatically signs up for all the tests
/// Prints the result of execution
async fn run_auto_sign_up(is_loop: bool) -> Result<(),()> {
    info!("Fetching credentials from config file.");
    let config_path = get_config_path(CONFIG_DIR, CONFIG_FILE);
    

    let credentials;

    loop {
        let request = get_valid_credentials(&config_path);
        if let Some(data) = handle_request(is_loop, request.await) {
            credentials = data;
            break;
        }
    }

    let access_token = credentials.access_token.expect("Access token should be present");
    let registration_result;
    loop {
        let request = api::register_for_tests(&access_token, api::REGISTERED_COURSE_URL, api::TEST_COURSE_URL, api::TEST_REGISTRATION_URL);
        if let Some(data) = handle_request(is_loop, request.await) {
            registration_result = data;
            break;
        }
    }
    
    
    let course_korte_naam_result: Vec<String> = registration_result.iter()
        .map(|test_list| test_list.cursus_korte_naam.clone())
        .collect();
    if course_korte_naam_result.is_empty() {
        info!("No exams were enrolled for.");
    }
    else {
        info!("Successfully enrolled for the following exams: {:?}", course_korte_naam_result);
        // Send desktop notification
        for course_name in course_korte_naam_result {
            show_notification(&course_name);
        }
    }
    Ok(())
}

fn show_notification(course_name: &str) {
    Notification::new()
        .summary("Exam Registration Success")
        .body(&format!("You have been successfully registered for the exam: {}", course_name))
        .icon("info")
        .show()
        .unwrap();
}

fn handle_request<R, E: ToString>(is_loop: bool, request: Result<R, E>) -> Option<R> {
    match request {
        Ok(data) => {
            return Some(data);
        }
        Err(e) => {
            if !is_loop {
                panic!("{}", "A network error likely occured".red().bold());
            }
            // Logs the error and wait 5 seconds before continuing
            error!("{}", e.to_string());
            thread::sleep(time::Duration::from_secs(5));
            return None;           
        }
    }
}

/// Returns the path to the user's home directory, combined with a hidden directory `config_dir`
/// and the config file `config_file`
fn get_config_path(config_dir: &str, config_file: &str) -> std::path::PathBuf {
    if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(config_dir).join(config_file)
    } else {
        // TODO: Better error handling
        panic!("Could not find home directory.");
    }
}

fn store_pid(process_id: Option<u32>) {
    let pid = PID {pid: process_id};
    let pid = serde_json::to_string(&pid).expect("Failed to serialise PID");
    let _ = std::fs::write(get_config_path(CONFIG_DIR, PID_FILE), pid);
}

/// Retrieves valid credentials with an access token.
/// If the access token is missing or invalid, it fetches a new one and updates the config.
async fn get_valid_credentials(config_path: &std::path::Path) -> Result<Credentials, Box<dyn std::error::Error>> {
    // Retrieve stored credentials (with or without access token)
    let mut credentials = load_credentials(config_path);

    loop {
        let is_cred_empty = credentials.username.is_none() && credentials.password.is_none() && credentials.access_token.is_none();

        // Only show the spinner if not in daemonized mode
        let pb = if env::var("DAEMONIZED").is_err() && !is_cred_empty {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            pb.set_message("Validating credentials...");
            Some(pb)
        } else {
            None
        };

        // If there's an access token, check if it's still valid
        if let Some(ref token) = credentials.access_token {
            let is_valid = api::is_user_authenticated(token, api::REGISTERED_COURSE_URL)
                .await
                .unwrap_or(false);

            if let Some(pb) = pb.as_ref() {
                pb.finish_and_clear();
            }
            if is_valid {
                return Ok(credentials);
            }
        }

        // Check if username and password exist
        match (&credentials.username, &credentials.password) {
        // Access token is missing or invalid; prompt for correct credentials if needed
            (Some(username), Some(password)) => {
                match api::get_access_token(username, password).await {
                    Ok(new_token) => {
                        credentials.access_token = Some(new_token);
                        save_credentials(&credentials, config_path);
                        if let Some(pb) = pb.as_ref() {
                            pb.finish_and_clear();
                        }
                        // TODO: Print might be problematic for autorun
                        println!("{}", "Success: Credentials are valid!".green().bold());
                        return Ok(credentials);
                    }
                    Err(e) => {
                        // If it is a connection error, the error needs to be thrown
                        if e.to_string().contains("error sending request") {
                            return Err(e);
                        }

                        if let Some(pb) = pb.as_ref() {
                            pb.finish_and_clear();
                        }
                        if !is_cred_empty {
                            // TODO: problematic for autorun.
                            eprintln!("{}", "Login failed: username or password incorrect. Please try again.".red().bold());
                        }
                        credentials = prompt_for_credentials();
                    }
                }
            }
            _ => {
                credentials = prompt_for_credentials();
            }
        }
    }
}

/// Loads credentials from config file or prompts the user to enter them if missing.
// TODO: Test load_credentials() with input from stdin
fn load_credentials(config_path: &std::path::Path) -> Credentials {
    if let Ok(data) = std::fs::read_to_string(&config_path) {
        if let Ok(credentials) = serde_json::from_str::<Credentials>(&data) {
            return credentials;
        }
    }

    prompt_for_credentials()
}

/// Prompts the user for their username and password.
fn prompt_for_credentials() -> Credentials {
    let mut username = String::new();

    print!("Username: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut username).expect("Couldn't read username");

    print!("Password: ");
    let _ = io::stdout().flush();
    let password = rpassword::read_password().expect("Failed to read password");

    Credentials {
        username: Some(username.trim().to_string()),
        password: Some(password.trim().to_string()),
        access_token: None,
    }
}

/// Saves updated credentials to the config file
fn save_credentials(credentials: &Credentials, config_path: &std::path::Path) {
    let serialized = serde_json::to_string(&credentials).expect("Failed to serialize credentials");
    std::fs::create_dir_all(config_path.parent().expect("Failed to get parent directory"))
        .expect("Failed to create config directory");
    std::fs::write(config_path, serialized).expect("Failed to save credentials");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Set up a temporary directory as `HOME` to test whether `get_config_path()`
    /// returns the accurate path
    #[test]
    fn test_get_config_path() {
        let temp_home = tempdir().expect("Failed to create temp directory");
        env::set_var("HOME", &temp_home.path());

        let config_path = get_config_path(CONFIG_DIR, CONFIG_FILE);

        let expected_path = temp_home.path().join(CONFIG_DIR).join(CONFIG_FILE);
        assert_eq!(expected_path, config_path);
    }

    /// Test depends on `save_credentials()`
    #[test]
    fn test_delete_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: Some("testtoken".to_string()),
        };

        save_credentials(&credentials, &config_path.as_path());

        delete_credentials(config_path.as_path());

        let saved_data = std::fs::read_to_string(&config_path).unwrap();
        let saved_credentials: Credentials = serde_json::from_str(&saved_data).unwrap();

        assert_eq!(saved_credentials.username, None);
        assert_eq!(saved_credentials.password, None);
        assert_eq!(saved_credentials.access_token, None);
    }

    #[test]
    fn test_save_credentials() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: Some("testtoken".to_string()),
        };

        save_credentials(&credentials, &config_path);

        let saved_data = std::fs::read_to_string(&config_path).unwrap();
        let saved_credentials: Credentials = serde_json::from_str(&saved_data).unwrap();

        assert_eq!(saved_credentials.username.unwrap(), "testuser");
        assert_eq!(saved_credentials.password.unwrap(), "testpassword");
        assert_eq!(saved_credentials.access_token.unwrap(), "testtoken");
    }

    /// Set up a temp `CONFIG_FILE` file with test credentials to assert whether `get_credentials()`
    /// can read from the file and return the accurate `username` and `password`
    #[test]
    fn test_load_credentials_with_valid_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let config_file_path = temp_dir.path().join(CONFIG_FILE);

        let credentials = Credentials {
            username: Some("testuser".to_string()),
            password: Some("testpassword".to_string()),
            access_token: None
        };
        let serialized = serde_json::to_string(&credentials)
            .expect("Failed to serialize credentials");
        std::fs::create_dir_all(config_file_path.parent().unwrap()).unwrap();
        let mut file = std::fs::File::create(&config_file_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        let result = load_credentials(&*config_file_path);

        assert_eq!(result.username.unwrap(), "testuser");
        assert_eq!(result.password.unwrap(), "testpassword");
    }
}
