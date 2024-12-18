mod api;
mod controller;
mod creds;
mod models;
use crate::controller::Controller;
#[cfg(target_os = "windows")]
mod registry;
use ::time::UtcOffset;
use api::Api;
use clap::{Parser, Subcommand};
use colored::*;
use creds::CredentialManager;
use log::{error, info, warn};
use notify_rust::Notification;
use serde::{Deserialize, Serialize};
use simplelog::*;
use std::env;
#[cfg(not(target_os = "windows"))]
use std::io;
#[cfg(not(target_os = "windows"))]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;
#[cfg(target_os = "windows")]
use std::process::Stdio;
use thiserror::Error;
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[derive(Serialize, Deserialize)]
struct Pid {
    pid: Option<u32>,
}

#[derive(Parser)]
#[command(
    name = "TUEnroll CLI",
    version,
    about = "Automate your TU Delft exam registrations"
)]
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
        #[arg(short, long, default_value_t = false)]
        boot: bool,
    },
    /// Stops any running background test checking process.
    Stop,
    /// Runs the check process one time and displays results.
    Run,
    /// Displays the current status.
    Status,
    /// Change username and password
    Change,
    /// Delete any saved credentials
    Delete,
    /// Show the logs of the application
    Log,
}

const APP_NAME: &str = "tuenroll";
const CONFIG_DIR: &str = ".tuenroll";
const PID_FILE: &str = "process.json";
const LAST_CHECK_FILE: &str = "last_check.json";
const LOG_FILE: &str = "tuenroll.log";
const LOGO: &str = "logo.png";

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Network request failed: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    #[error("Failed to decode JSON: {0}")]
    JsonDecodeError(#[from] serde_json::Error),
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Keyring error: {0}")]
    KeyringError(#[from] keyring::Error),

    #[error("Credentials not found")]
    CredentialsNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Input Error: {0}")]
    InputError(String),
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("API Error: {0}")]
    ApiError(#[from] ApiError),

    #[error("Credentials Error: {0}")]
    CredentialError(#[from] CredentialError),

    #[error("Configuration Error: {0}")]
    ConfigError(String),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON Error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[allow(clippy::zombie_processes)]
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("{}", e);
        println!("{}", e.to_string().red().bold());
    }
}

async fn run() -> Result<(), CliError> {
    // Check if it's the first setup
    if is_first_setup(dirs::home_dir)? {
        display_logo();

        println!("{}", "Welcome to TUEnroll CLI!".bright_cyan());
        println!(
            "{}",
            "Automate your TU Delft exam registrations. Let's get you set up!".bright_cyan()
        );

        download_logo().await?;
        // Sets up the registry values to be able to display notifications with a logo
        #[cfg(target_os = "windows")]
        setup_registry()?;
    }

    set_up_logging()?;

    let cli = Cli::parse();

    let manager = CredentialManager::new(Api::new()?, APP_NAME.to_string());

    // Wrap `exit()` function with a function returning `?` instead of experimental `!`
    let exit_fn = |code: i32| {
        exit(code);
    };

    match &cli.command {
        Commands::Run => {
            info!("Starting the 'Run' command execution.");
            let mut run_controller =
                Controller::new(Api::new()?, exit_fn, manager, false, false, |body: &str| {
                    show_notification(body);
                });
            let _ = run_controller.get_credentials().await;
            match run_controller.run_auto_sign_up().await {
                Ok(()) => {
                    println!("{}", "Success: Exam check ran.".green().bold());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Start { interval, boot } => {
            info!("Starting the 'Start' command execution.");

            let mut start_controller =
                Controller::new(Api::new()?, exit_fn, manager, true, *boot, |body: &str| {
                    show_notification(body);
                });

            // WARNING: Do not have any print statements or the command and process will stop working detached
            if env::var("DAEMONIZED").err().is_some() {
                let _ = start_controller.get_credentials().await;

                // Checks whether a process was running, if not don't run the program
                if *boot && get_stored_pid(get_config_path)?.is_none() {
                    info!("Boot is enabled but no process was running. Stopping execution");
                    return Ok(()); // return
                } else if !boot {
                    info!("Setting boot up");
                    setup_run_on_boot(interval);
                }
                //  Check that no other process is running
                if process_is_running()? {
                    println!("Another process is already running");
                    return Ok(()); //return
                }
                info!("Spawning daemon process with interval: {}", interval);
                let mut command = Command::new(env::current_exe()?);

                command
                    .args(["start", format!("--interval={}", interval).as_str()])
                    .env("DAEMONIZED", "1");

                #[cfg(target_os = "windows")]
                command.creation_flags(0x08000000);

                let child = command.spawn()?;

                store_pid(Some(child.id()), get_config_path)?;
                //println!("{}", "Success: Service started.".green().bold());
                info!("Daemon process started with PID: {}", child.id());
                if !boot {
                    println!("Command 'Start' was successfully started");
                }
            } else {
                info!("Daemon process enabled: starting loop");
                start_controller.run_loop(*interval * 3600, 3600).await;
            }
            Ok(()) // return
        }
        Commands::Stop => {
            info!("Stopping the cli.");
            let stopped_process = stop_program()?;
            if stopped_process.is_none() {
                eprintln!("{}", "No running service to stop.".red().bold());
                Ok(())
            } else {
                println!(
                    "{}",
                    "Background service has been successfully stopped"
                        .green()
                        .bold()
                );
                Ok(())
            }
        }
        Commands::Status => {
            info!("Fetching the current status.");
            let process_status = if let Some(Some(pid)) =
                process_is_running()?.then(|| get_stored_pid(get_config_path).ok()?)
            {
                format!("Running (PID: {}).", pid).green()
            } else {
                "Not running.".to_string().red()
            };

            let credentials_status = if manager.has_credentials()? {
                "Credentials are saved.".to_string().green()
            } else {
                "No credentials saved.".to_string().red()
            };

            let network_status = match check_network_status(api::BASE_URL).await {
                Ok(()) => "Network is up.".green(),
                Err(_) => "Network is down.".red(),
            };

            let last_check_status = match get_last_check_time(get_config_path)? {
                Some(time) => time.green(),
                None => "No previous checks recorded.".to_string().red(),
            };

            println!("Current Status:");
            println!("  Service: {}", process_status);
            println!("  Credentials: {}", credentials_status);
            println!("  Network: {}", network_status);
            println!("  Last check: {}", last_check_status);
            info!("Displayed the current status.");
            Ok(())
        }
        Commands::Change => {
            info!("Changing credentials.");
            let _ = manager.delete_credentials();
            let mut change_controller =
                Controller::new(Api::new()?, exit_fn, manager, false, false, |body: &str| {
                    show_notification(body);
                });
            let _ = change_controller.get_credentials().await;
            Ok(())
        }
        Commands::Delete => {
            info!("Deleting credentials.");
            let _ = manager.delete_credentials();
            println!("{}", "Success: Credentials deleted!".green().bold());
            Ok(())
        }
        Commands::Log => {
            info!("Displaying the logs.");
            let log_path = get_config_path(CONFIG_DIR, LOG_FILE)?;
            match std::fs::read_to_string(log_path) {
                Ok(log_contents) => {
                    print!("{}", log_contents);
                    info!("Displayed the logs successfully.");
                }
                Err(e) => {
                    eprintln!("{}", format!("Could not read log file: {}", e).red().bold());
                    error!("Error while printing the logs");
                }
            }
            Ok(())
        }
    }
}

fn is_first_setup<F: Fn() -> Option<PathBuf>>(home_dir_fn: F) -> Result<bool, CliError> {
    let config_path = home_dir_fn()
        .ok_or_else(|| CliError::ConfigError("Unable to find home directory".to_string()))?
        .join(CONFIG_DIR);

    if !config_path.exists() {
        return Ok(true); // First setup
    }
    Ok(false) // Not the first setup
}

fn set_up_logging() -> Result<(), CliError> {
    let log_path = get_config_path(CONFIG_DIR, LOG_FILE)?;
    let parent = log_path
        .parent()
        .ok_or_else(|| CliError::ConfigError("No parent directory".to_string()))?;
    std::fs::create_dir_all(parent)?;

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    // Current time in local timezone
    let offset = chrono::Local::now().offset().local_minus_utc();

    let time_offset = UtcOffset::from_whole_seconds(offset)
        .map_err(|_| CliError::ConfigError("Failed to create time offset".to_string()))?;

    let config = ConfigBuilder::new()
        .set_time_format_custom(simplelog::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .set_time_offset(time_offset)
        .build();

    CombinedLogger::init(vec![WriteLogger::new(LevelFilter::Info, config, log_file)])
        .map_err(|e| CliError::ConfigError(format!("Failed to initialize logger: {}", e)))?;

    Ok(())
}

async fn check_network_status(url: &str) -> Result<(), ApiError> {
    let response = reqwest::get(url).await?;

    if response.status().is_server_error() {
        return Err(ApiError::InvalidResponse(format!(
            "Server Error: HTTP {}",
            response.status()
        )));
    }

    Ok(())
}

fn store_last_check_time<F: Fn(&str, &str) -> Result<PathBuf, CliError>>(
    get_config_path: F,
) -> Result<(), CliError> {
    let last_check_time = chrono::Utc::now().to_rfc3339();
    let path = get_config_path(CONFIG_DIR, LAST_CHECK_FILE)?;
    let data = serde_json::json!({ "last_check": last_check_time });

    let json_string = serde_json::to_string(&data)?;
    std::fs::write(path, json_string)?;

    Ok(())
}

fn get_last_check_time<F: Fn(&str, &str) -> Result<PathBuf, CliError>>(
    get_config_path: F,
) -> Result<Option<String>, CliError> {
    let path = get_config_path(CONFIG_DIR, LAST_CHECK_FILE)?;

    let content = std::fs::read_to_string(path)?;
    let data = serde_json::from_str::<serde_json::Value>(&content)?;

    if let Some(last_check) = data.get("last_check").and_then(|v| v.as_str()) {
        // Parse the stored time and calculate the difference
        if let Ok(last_check_time) = chrono::DateTime::parse_from_rfc3339(last_check) {
            return Ok(Some(time_ago(last_check_time)));
        }
    }
    Ok(None)
}

/// Helper function to calculate time difference
fn time_ago(last_check_time: chrono::DateTime<chrono::FixedOffset>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(last_check_time.with_timezone(&chrono::Utc));

    if duration.num_seconds() < 60 {
        format!("{} seconds ago", duration.num_seconds())
    } else if duration.num_minutes() < 60 {
        return format!("{} minutes ago", duration.num_minutes());
    } else if duration.num_hours() < 24 {
        return format!("{} hours ago", duration.num_hours());
    } else if duration.num_days() < 30 {
        return format!("{} days ago", duration.num_days());
    } else if duration.num_days() < 365 {
        return format!("{} months ago", duration.num_days() / 30);
    } else {
        return format!("{} years ago", duration.num_days() / 365);
    }
}

fn display_logo() {
    println!(
        "{}",
        r"
 ________  __    __  ________                                __  __ 
|        \|  \  |  \|        \                              |  \|  \
 \$$$$$$$$| $$  | $$| $$$$$$$$ _______    ______    ______  | $$| $$
   | $$   | $$  | $$| $$__    |       \  /      \  /      \ | $$| $$
   | $$   | $$  | $$| $$  \   | $$$$$$$\|  $$$$$$\|  $$$$$$\| $$| $$
   | $$   | $$  | $$| $$$$$   | $$  | $$| $$   \$$| $$  | $$| $$| $$
   | $$   | $$__/ $$| $$_____ | $$  | $$| $$      | $$__/ $$| $$| $$
   | $$    \$$    $$| $$     \| $$  | $$| $$       \$$    $$| $$| $$
    \$$     \$$$$$$  \$$$$$$$$ \$$   \$$ \$$        \$$$$$$  \$$ \$$
    "
        .bright_green()
    );
}

fn get_stored_pid<F: Fn(&str, &str) -> Result<PathBuf, CliError>>(
    get_config_path: F,
) -> Result<Option<u32>, CliError> {
    let path = get_config_path(CONFIG_DIR, PID_FILE)?;
    if !path.exists() {
        return Ok(None); // Return None if the file doesn't exist
    }
    let pid_content = std::fs::read_to_string(path)?;
    let pid: Pid = serde_json::from_str(&pid_content)?;
    Ok(pid.pid)
}

fn stop_program() -> Result<Option<u32>, CliError> {
    let pid = match get_stored_pid(get_config_path)? {
        Some(pid) => pid,
        None => return Ok(None),
    };
    info!("Attempting to stop the process with PID: {}", pid);

    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .stdout(Stdio::null()) // Suppress standard output
        .stderr(Stdio::null()) // Suppress standard error
        .spawn()?;

    #[cfg(not(target_os = "windows"))]
    Command::new("kill").arg(pid.to_string()).spawn()?;

    info!("Successfully stopped the process with PID: {}", pid);
    store_pid(None, get_config_path)?;
    Ok(Some(pid))
}

fn process_is_running() -> Result<bool, CliError> {
    let stored_pid = match get_stored_pid(get_config_path) {
        Ok(Some(pid)) => pid,
        Ok(None) => return Ok(false),
        Err(e) => return Err(e),
    };

    let stored_pid = stored_pid.to_string();

    #[cfg(not(target_os = "windows"))]
    {
        let process = Command::new("ps")
            .args(["-p", stored_pid.as_str()])
            .output()
            .map_err(CliError::IoError)?;
        if process.status.success() {
            info!("Process with PID {} is running.", stored_pid);
            Ok(true)
        } else {
            warn!(
                "Process with PID {} is not running. Cleaning up PID store.",
                stored_pid
            );
            store_pid(None, get_config_path)?;
            Ok(false)
        }
    }

    #[cfg(target_os = "windows")]
    {
        let process = Command::new("tasklist")
            .arg("/FI")
            .raw_arg(format!("\"PID eq {}\"", stored_pid).as_str())
            .output()
            .map_err(CliError::IoError)?;

        let output = String::from_utf8(process.stdout)
            .map_err(|e| CliError::ConfigError(format!("Invalid UTF-8 output: {}", e)))?;
        if output.contains("No tasks are running") {
            warn!(
                "Process with PID {} is not running. Cleaning up PID store.",
                stored_pid
            );
            store_pid(None, get_config_path)?;
            Ok(false)
        } else {
            info!("Process with PID {} is running.", stored_pid);
            Ok(true)
        }
    }
}

fn show_notification(body: &str) {
    let mut notification = Notification::new();

    let notification = notification.body(body).timeout(5 * 1000); // 5 seconds

    #[cfg(target_os = "windows")]
    let notification = notification.app_id(APP_NAME);

    #[cfg(target_os = "linux")]
    {
        let logo_path_result = get_config_path(CONFIG_DIR, LOGO);
        if let Ok(path) = logo_path_result {
            if let Some(str_path) = path.to_str() {
                notification.image_path(str_path);
            } else {
                error!("Invalid path for logo: {}", path.display());
            }
        } else {
            error!(
                "Failed to get config path for logo: {}",
                logo_path_result.unwrap_err()
            );
        }
    }

    if let Err(e) = notification.show() {
        error!("Failed to show notification: {}", e);
    }
}

/// Returns the path to the user's home directory, combined with a hidden directory `config_dir`
/// and the config file `config_file`
fn get_config_path(config_dir: &str, config_file: &str) -> Result<PathBuf, CliError> {
    dirs::home_dir()
        .ok_or_else(|| CliError::ConfigError("Could not find home directory.".to_string()))
        .map(|home_dir| home_dir.join(config_dir).join(config_file))
}

fn store_pid<F: Fn(&str, &str) -> Result<PathBuf, CliError>>(
    process_id: Option<u32>,
    get_config_path: F,
) -> Result<(), CliError> {
    let pid = Pid { pid: process_id };
    let pid = serde_json::to_string(&pid)?;
    std::fs::write(get_config_path(CONFIG_DIR, PID_FILE)?, pid)?;
    Ok(())
}

/// Sets up the program to run on boot
fn setup_run_on_boot(interval: &u32) {
    #[cfg(target_os = "windows")]
    let result = run_on_boot_windows(interval);

    #[cfg(not(target_os = "windows"))]
    let result = run_on_boot_linux(interval);

    if result.is_ok() {
        info!("Boot setup was succesful");
    } else {
        error!("Boot setup encountered an error: {:?}", result.err())
    }
}

#[cfg(target_os = "windows")]
fn run_on_boot_windows(interval: &u32) -> Result<(), CliError> {
    let exe_path = env::current_exe()?;
    // Path to the startup folder
    let startup_path = format!(
        r"{}\Microsoft\Windows\Start Menu\Programs\Startup\{}.lnk",
        env::var("APPDATA").map_err(|_| CliError::ConfigError(
            "APPDATA environment variable not found".to_string()
        ))?,
        APP_NAME
    );

    let args = format!("start --interval={interval} --boot");

    // Use PowerShell to create a shortcut in the Startup folder
    let command = format!(
        r#"$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('{}'); $sc.TargetPath = '{}'; $sc.Arguments = '{}'; $sc.WindowStyle = 7; $sc.Save()"#,
        startup_path,
        exe_path.to_string_lossy(),
        args
    );

    Command::new("powershell")
        .args(["-Command", &command])
        .output()?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn run_on_boot_linux(interval: &u32) -> Result<(), CliError> {
    let exe_path = env::current_exe()?;
    let exe_path = exe_path.to_string_lossy();

    let autostart_dir = dirs::config_dir()
        .ok_or_else(|| CliError::ConfigError("Config directory not found".to_string()))?
        .join("autostart");

    std::fs::create_dir_all(&autostart_dir)?;

    // Create the .desktop file
    let desktop_file_path = autostart_dir.join(APP_NAME.to_string() + ".desktop");
    let desktop_entry = format!(
        "[Desktop Entry]\nType=Application\nName={}\nExec={}\nX-GNOME-Autostart-enabled=true\n",
        APP_NAME,
        exe_path + format!(" start --boot --interval={interval}").as_str()
    );

    let mut file = std::fs::File::create(&desktop_file_path)?;
    file.write_all(desktop_entry.as_bytes())?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn setup_registry() -> Result<(), CliError> {
    use registry::RegistryHandler;

    let config_path = get_config_path(CONFIG_DIR, LOGO)?;
    let config_path_str = config_path.to_str().ok_or_else(|| {
        CliError::ConfigError("Failed to convert config path to a string.".to_string())
    })?;

    if registry::registry(
        config_path_str,
        APP_NAME,
        &RegistryHandler::new(RegKey::predef(HKEY_CURRENT_USER)),
    )
    .is_ok()
    {
        info!("Registry succesfully setup.");
    } else {
        error!("Registry setup was unsuccesful");
    }
    Ok(())
}

async fn download_logo() -> Result<(), CliError> {
    let logo_path = get_config_path(CONFIG_DIR, LOGO)?;

    if logo_path.exists() {
        return Ok(());
    }

    let logo_url = "https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/logo.png";

    let parent = logo_path
        .parent()
        .ok_or_else(|| CliError::ConfigError("No parent directory".to_string()))?;
    std::fs::create_dir_all(parent)?;

    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&logo_path)?;

    let response = reqwest::get(logo_url)
        .await
        .map_err(|e| CliError::ApiError(ApiError::NetworkError(e)))?;

    info!("Downloading logo.");

    let bytes = response
        .bytes()
        .await
        .map_err(|e| CliError::ApiError(ApiError::NetworkError(e)))?;
    std::fs::write(&logo_path, bytes)?;

    info!("Writing logo to file");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};
    use std::fs;

    #[test]
    fn test_get_config_path() {
        let home = tempfile::TempDir::new().unwrap();
        // Set HOME variable for Linux/macOS, and USERPROFILE for Windows
        if cfg!(target_os = "windows") {
            env::set_var("USERPROFILE", home.path());
        } else {
            env::set_var("HOME", home.path());
        }

        let path = get_config_path(CONFIG_DIR, PID_FILE).unwrap();

        // Using `MAIN_SEPARATOR` because of differences between Linux/macOS and Windows
        let expected_subpath = ".tuenroll".to_string()
            + std::path::MAIN_SEPARATOR.to_string().as_str()
            + "process.json";
        assert!(path.to_str().unwrap().contains(&expected_subpath));
    }

    #[test]
    fn test_is_first_setup() {
        let home = tempfile::TempDir::new().unwrap();

        let mock_home_dir_fn = || Some(home.path().to_path_buf());

        assert!(is_first_setup(mock_home_dir_fn).unwrap()); // `.tuenroll` not yet created

        let config_path = home.path().to_owned().join(CONFIG_DIR);
        fs::create_dir_all(&config_path).unwrap();

        assert!(!is_first_setup(mock_home_dir_fn).unwrap()); // `.tuenroll` now exists
    }

    /// Tests related to `Status` command:
    /// 1. `check_network_status()`
    /// 2. `store_last_check_time()`
    /// 3. `get_last_check_time()`
    /// 4. `time_ago()`
    mod status_tests {
        use super::*;
        #[tokio::test]
        async fn test_network_is_up() {
            let mut server = mockito::Server::new_async().await;
            let _mock = server.mock("GET", "/test").with_status(200).create(); // Network is up (HTTP 200 OK)

            let result = check_network_status(&*(server.url() + "/test")).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_network_is_down() {
            // Non-existent url
            let result =
                check_network_status("https://nonexistent-domain-that-will-never-exist.xyz").await;
            assert!(result.is_err());

            // 5xx error
            let mut server = mockito::Server::new_async().await;
            let _mock = server.mock("GET", "/test").with_status(500).create(); // Network is up (HTTP 500 Internal Server Error)

            let result = check_network_status(&*(server.url() + "/test")).await;
            assert!(result.is_err());
        }

        #[test]
        fn test_store_last_check_time() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            store_last_check_time(mock_get_config_path).unwrap();
            let file_path = temp_dir.path().join(LAST_CHECK_FILE);

            assert!(file_path.exists()); // last check file should exist

            let content = std::fs::read_to_string(&file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert!(parsed.get("last_check").is_some());

            let timestamp = parsed["last_check"].as_str().unwrap();
            assert!(chrono::DateTime::parse_from_rfc3339(timestamp).is_ok());
        }

        #[test]
        fn test_get_last_check_time() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            store_last_check_time(mock_get_config_path).unwrap();

            let result = get_last_check_time(mock_get_config_path).unwrap();

            let last_check_time = Utc::now();
            let expected_str = time_ago(DateTime::from(last_check_time));

            assert_eq!(result, Some(expected_str));
        }

        #[test]
        fn test_time_ago() {
            let now = Utc::now();

            let result = time_ago(DateTime::from(now - Duration::seconds(30)));
            assert_eq!(result, "30 seconds ago");

            let result = time_ago(DateTime::from(now - Duration::minutes(5)));
            assert_eq!(result, "5 minutes ago");

            let result = time_ago(DateTime::from(now - Duration::hours(3)));
            assert_eq!(result, "3 hours ago");

            let result = time_ago(DateTime::from(now - Duration::days(7)));
            assert_eq!(result, "7 days ago");

            let result = time_ago(DateTime::from(now - Duration::days(60)));
            assert_eq!(result, "2 months ago");

            let result = time_ago(DateTime::from(now - Duration::days(400)));
            assert_eq!(result, "1 years ago");
        }
    }

    /// Tests related to `PID` management:
    /// 1. `get_stored_pid()`
    /// 2. `store_pid()`
    mod pid_tests {
        use super::*;
        #[test]
        fn test_get_stored_pid() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            // write to file
            let mock_pid = Pid { pid: Some(1234) };
            let pid_file_path = temp_dir.path().join(PID_FILE);
            let pid_data = serde_json::to_string(&mock_pid).unwrap();
            fs::write(pid_file_path, pid_data).unwrap();

            let result = get_stored_pid(mock_get_config_path).unwrap();
            assert_eq!(result, Some(1234));
        }

        #[test]
        fn test_get_stored_pid_no_pid_file() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            let result = get_stored_pid(mock_get_config_path).unwrap();

            assert_eq!(result, None);
        }

        #[test]
        fn test_store_pid() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            store_pid(Some(1234), mock_get_config_path).unwrap();

            let pid_file_path = temp_dir.path().join(PID_FILE);
            assert!(pid_file_path.exists()); // verify file was created

            let content = fs::read_to_string(pid_file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert_eq!(parsed["pid"], 1234);
        }

        #[test]
        fn test_store_pid_none() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| -> Result<PathBuf, CliError> {
                    Ok(temp_dir.path().join(filename))
                };

            store_pid(None, mock_get_config_path).unwrap();

            let pid_file_path = temp_dir.path().join(PID_FILE);
            assert!(pid_file_path.exists()); // verify file was created

            let content = fs::read_to_string(pid_file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert!(parsed["pid"].is_null());
        }
    }
}
