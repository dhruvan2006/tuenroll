mod api;
mod controller;
mod creds;
mod models;
use crate::controller::Controller;
#[cfg(target_os = "windows")]
mod registry;
use crate::api::ApiTrait;
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
use std::{process::Command, thread, time};
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

#[allow(clippy::zombie_processes)]
#[tokio::main]
async fn main() {
    // Check if it's the first setup
    if is_first_setup(dirs::home_dir) {
        display_logo();

        println!("{}", "Welcome to TUEnroll CLI!".bright_cyan());
        println!(
            "{}",
            "Automate your TU Delft exam registrations. Let's get you set up!".bright_cyan()
        );

        download_logo().await;
        // Sets up the registry values to be able to display notifications with a logo
        #[cfg(target_os = "windows")]
        setup_registry();
    }

    set_up_logging();

    let cli = Cli::parse();

    let manager = CredentialManager::new(Api::new(), APP_NAME.to_string());

    // Wrap `exit()` function with a function returning `?` instead of experimental `!`
    let exit_fn = |code: i32| {
        exit(code);
    };

    match &cli.command {
        Commands::Run => {
            info!("Starting the 'Run' command execution.");
            let run_controller = Controller::new(Api::new(), exit_fn, manager, false, false);
            let _ = run_controller.get_credentials().await;
            match run_controller.run_auto_sign_up(show_notification).await {
                Ok(()) => println!("{}", "Success: Exam check ran.".green().bold()),
                Err(err) if err == "Invalid credentials" => {
                    // Invalid credentials should definitely never happen
                    println!("Invalid credentials detected")
                }
                Err(_) => println!("{}", "Failure: A network error occured".red().bold()),
            }
        }
        Commands::Start { interval, boot } => {
            info!("Starting the 'Start' command execution.");

            let start_controller = Controller::new(Api::new(), exit_fn, manager, true, *boot);

            // WARNING: Do not have any print statements or the command and process will stop working detached
            if env::var("DAEMONIZED").err().is_some() {
                let _ = start_controller.get_credentials().await;

                // Checks whether a process was running, if not don't run the program
                if *boot && get_stored_pid(get_config_path).is_none() {
                    info!("Boot is enabled but no process was running. Stopping execution");
                    return;
                } else if !boot {
                    info!("Setting boot up");
                    setup_run_on_boot(interval);
                }
                //  Check that no other process is running
                if process_is_running() {
                    println!("Another process is already running");
                    return;
                }
                info!("Spawning daemon process with interval: {}", interval);
                let mut command = Command::new(env::current_exe().unwrap());

                command
                    .args(["start", format!("--interval={}", interval).as_str()])
                    .env("DAEMONIZED", "1");

                #[cfg(target_os = "windows")]
                command.creation_flags(0x08000000);

                let child = command.spawn().unwrap();

                store_pid(Some(child.id()), get_config_path);
                //println!("{}", "Success: Service started.".green().bold());
                info!("Daemon process started with PID: {}", child.id());
                if !boot {
                    println!("Command 'Start' was successfully started");
                }
                return;
            } else {
                info!("Daemon process enabled: starting loop");
                start_controller
                    .run_loop(&mut show_notification, interval * 3600, 3600)
                    .await;
            }
        }
        Commands::Stop => {
            info!("Stopping the cli.");
            let stopped_process = stop_program();
            if stopped_process.is_none() {
                eprintln!("{}", "Error: No running service to stop.".red());
            } else {
                println!(
                    "{}",
                    "Background service has been successfully stopped"
                        .green()
                        .bold()
                );
            }
        }
        Commands::Status => {
            info!("Fetching the current status.");
            let process_status = if let Some(Some(pid)) =
                process_is_running().then(|| get_stored_pid(get_config_path))
            {
                format!("Running (PID: {}).", pid).green()
            } else {
                "Not running.".to_string().red()
            };

            let credentials_status = if manager.has_credentials() {
                "Credentials are saved.".to_string().green()
            } else {
                "No credentials saved.".to_string().red()
            };

            let network_status = match check_network_status(api::BASE_URL).await {
                Ok(()) => "Network is up.".green(),
                Err(_) => "Network is down.".red(),
            };

            let last_check_status = match get_last_check_time(get_config_path) {
                Some(time) => time.green(),
                None => "No previous checks recorded.".to_string().red(),
            };

            println!("Current Status:");
            println!("  Service: {}", process_status);
            println!("  Credentials: {}", credentials_status);
            println!("  Network: {}", network_status);
            println!("  Last check: {}", last_check_status);
            info!("Displayed the current status.");
        }
        Commands::Change => {
            info!("Changing credentials.");
            manager.delete_credentials();
            let change_controller = Controller::new(Api::new(), exit_fn, manager, false, false);
            let _ = change_controller.get_credentials().await;
        }
        Commands::Delete => {
            info!("Deleting credentials.");
            manager.delete_credentials();
            println!("{}", "Success: Credentials deleted!".green().bold());
        }
        Commands::Log => {
            info!("Displaying the logs.");
            let log_path = get_config_path(CONFIG_DIR, LOG_FILE);
            match std::fs::read_to_string(log_path) {
                Ok(log_contents) => {
                    print!("{}", log_contents);
                    info!("Displayed the logs successfully.");
                }
                Err(e) => {
                    eprintln!("{}", format!("Error: Could not read log file: {}", e).red());
                    error!("Error while printing the logs");
                }
            }
        }
    }
}

fn is_first_setup<F: Fn() -> Option<PathBuf>>(home_dir_fn: F) -> bool {
    let config_path = home_dir_fn()
        .expect("Unable to find home directory")
        .join(CONFIG_DIR);

    if !config_path.exists() {
        return true; // First setup
    }
    false // Not the first setup
}

fn set_up_logging() {
    let log_path = get_config_path(CONFIG_DIR, LOG_FILE);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create log directory");
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .unwrap();

    // Current time in local timezone
    let offset = chrono::Local::now().offset().local_minus_utc();

    let config = ConfigBuilder::new()
        .set_time_format_custom(simplelog::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .set_time_offset(UtcOffset::from_whole_seconds(offset).unwrap())
        .build();

    CombinedLogger::init(vec![
        // TermLogger::new(LevelFilter::Info, Config::default(), TerminalMode::Mixed, ColorChoice::Always),
        WriteLogger::new(LevelFilter::Info, config, log_file),
    ])
    .expect("Failed to initialize logger");

    // info!("Initialized the logger");
}

async fn check_network_status(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::get(url).await?;

    if response.status().is_server_error() {
        return Err(format!("Server Error: HTTP {}", response.status()).into());
    }

    Ok(())
}

fn store_last_check_time<F: Fn(&str, &str) -> PathBuf>(get_config_path: F) {
    let last_check_time = chrono::Utc::now().to_rfc3339();
    let path = get_config_path(CONFIG_DIR, LAST_CHECK_FILE);
    let data = serde_json::json!({ "last_check": last_check_time });

    match std::fs::write(path, serde_json::to_string(&data).unwrap()) {
        Ok(_) => info!("Last check time saved."),
        Err(e) => error!("Failed to save last check time: {}", e),
    }
}

fn get_last_check_time<F: Fn(&str, &str) -> PathBuf>(get_config_path: F) -> Option<String> {
    let path = get_config_path(CONFIG_DIR, LAST_CHECK_FILE);

    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(last_check) = data.get("last_check") {
                if let Some(last_check_str) = last_check.as_str() {
                    // Parse the stored time and calculate the difference
                    if let Ok(last_check_time) =
                        chrono::DateTime::parse_from_rfc3339(last_check_str)
                    {
                        return Some(time_ago(last_check_time));
                    }
                }
            }
        }
    }
    None
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

async fn run_loop<T: ApiTrait>(interval: &u32, manager: &CredentialManager<T>, is_boot: bool) {
    let _ = run_auto_sign_up(true, manager, is_boot).await;

    let mut start_time = std::time::SystemTime::now();
    loop {
        info!("Checking whether time interval is completed");
        if std::time::SystemTime::now()
            .duration_since(start_time)
            .unwrap()
            .as_secs()
            >= (interval * 3600).into()
        {
            info!("Running auto sign up");
            match run_auto_sign_up(true, manager, is_boot).await {
                Ok(_) => info!("Auto sign-up successful."),
                Err(err) if err == "Invalid credentials" => {
                    error!("Invalid credentials detected.");
                    show_notification("Your credentials are invalid. Run tuenroll start again")
                        .await;
                    break; // !!! Stops the background process !!!
                }
                Err(_) => {
                    error!("Failure: A network error occurred");
                }
            }
            start_time = std::time::SystemTime::now();
        }
        thread::sleep(time::Duration::from_secs(3600));
    }
}

fn get_stored_pid<F: Fn(&str, &str) -> PathBuf>(get_config_path: F) -> Option<u32> {
    if let Ok(pid) = std::fs::read_to_string(get_config_path(CONFIG_DIR, PID_FILE)) {
        if let Ok(pid) = serde_json::from_str::<Pid>(&pid) {
            return pid.pid;
        }
    }
    None
}

fn stop_program() -> Option<u32> {
    let pid = get_stored_pid(get_config_path);
    pid?;
    let pid = pid.unwrap();

    info!("Attempting to stop the process with PID: {}", pid);

    #[cfg(target_os = "windows")]
    let kill = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .stdout(Stdio::null()) // Suppress standard output
        .stderr(Stdio::null()) // Suppress standard error
        .spawn();

    #[cfg(not(target_os = "windows"))]
    let kill = Command::new("kill").arg(pid.to_string()).spawn();

    if let Err(e) = kill {
        error!("Failed to stop process with PID {}: {}", pid, e);
        return None;
    }

    info!("Successfully stopped the process with PID: {}", pid);
    store_pid(None, get_config_path);
    Some(pid)
}

fn process_is_running() -> bool {
    let stored_pid = get_stored_pid(get_config_path);
    if stored_pid.is_none() {
        return false;
    };

    let stored_pid = stored_pid.unwrap().to_string();

    #[cfg(not(target_os = "windows"))]
    {
        let process = Command::new("ps")
            .args(["-p", stored_pid.as_str()])
            .output()
            .expect("Error occured when running ps -p $PID");
        if process.status.success() {
            info!("Process with PID {} is running.", stored_pid);
            true
        } else {
            warn!(
                "Process with PID {} is not running. Cleaning up PID store.",
                stored_pid
            );
            store_pid(None, get_config_path);
            false
        }
    }

    #[cfg(target_os = "windows")]
    {
        let process = Command::new("tasklist")
            .arg("/FI")
            .raw_arg(format!("\"PID eq {}\"", stored_pid).as_str())
            .output()
            .expect("Error occured when running tasklist /FI \"PID eq $pid\"");

        if String::from_utf8(process.stdout)
            .unwrap()
            .contains("No tasks are running")
        {
            warn!(
                "Process with PID {} is not running. Cleaning up PID store.",
                stored_pid
            );
            store_pid(None, get_config_path);
            false
        } else {
            info!("Process with PID {} is running.", stored_pid);
            true
        }
    }
}

async fn get_credentials<T: ApiTrait>(
    manager: &CredentialManager<T>,
    is_loop: bool,
    is_boot: bool,
) -> Credentials {
    let credentials;

    loop {
        let request = manager.get_valid_credentials(
            Credentials::load_from_keyring,
            CredentialManager::<T>::prompt_for_credentials,
            !is_boot,
        );
        if let Some(data) = handle_request(is_loop, request.await, is_boot) {
            credentials = data;
            if !is_boot {
                println!("{}", "Credentials validated successfully!".green().bold());
            }
            break;
        }
    }

    credentials
}

/// Runs the auto signup fully once
/// Gets the credentials, the access token
/// Automatically signs up for all the tests
/// Prints the result of execution
async fn run_auto_sign_up<T: ApiTrait>(
    is_loop: bool,
    manager: &CredentialManager<T>,
    is_boot: bool,
) -> Result<(), String> {
    // Creds don't exist
    let credentials = manager
        .get_valid_credentials(
            Credentials::load_from_keyring,
            Credentials::default,
            !is_loop,
        )
        .await;
    if credentials.is_err() {
        return Err("Invalid credentials".to_string());
    }
    let credentials = credentials.unwrap();

    // Check if creds are valid
    if !manager
        .validate_stored_token(&credentials, api::REGISTERED_COURSE_URL)
        .await
        .map_err(|e| e.to_string())?
    {
        return Err("Invalid credentials".to_string());
    }

    let access_token = credentials
        .access_token
        .clone()
        .expect("Access token should be present");
    let registration_result;
    let api: Box<dyn ApiTrait> = Box::new(Api::new());
    loop {
        let request = api.register_for_tests(
            &access_token,
            api::REGISTERED_COURSE_URL,
            api::TEST_COURSE_URL,
            api::TEST_REGISTRATION_URL,
        );
        if let Some(data) = handle_request(is_loop, request.await, is_boot) {
            registration_result = data;
            break;
        }
    }

    let course_korte_naam_result: Vec<String> = registration_result
        .iter()
        .map(|test_list| test_list.cursus_korte_naam.clone())
        .collect();
    if course_korte_naam_result.is_empty() {
        info!("No exams were enrolled for.");
    } else {
        info!(
            "Successfully enrolled for the following exams: {:?}",
            course_korte_naam_result
        );
        // Send desktop notification
        for course_name in course_korte_naam_result {
            show_notification(&format!(
                "You have been successfully registered for the exam: {}",
                course_name
            ))
            .await;
        }
    }

    // Store the last check time
    store_last_check_time();

    Ok(())
}

async fn show_notification(body: &str) {
    download_logo().await;

    let mut notification = Notification::new();

    let notification = notification.body(body).timeout(5 * 1000); // 5 seconds

    #[cfg(target_os = "windows")]
    let notification = notification.app_id(APP_NAME);

    #[cfg(target_os = "linux")]
    let notification = notification.image_path(get_config_path(CONFIG_DIR, LOGO).to_str().unwrap());

    if let Err(e) = notification.show() {
        error!("Failed to show notification: {}", e);
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

fn store_pid<F: Fn(&str, &str) -> PathBuf>(process_id: Option<u32>, get_config_path: F) {
    let pid = Pid { pid: process_id };
    let pid = serde_json::to_string(&pid).expect("Failed to serialise PID");
    let _ = std::fs::write(get_config_path(CONFIG_DIR, PID_FILE), pid);
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
        error!("Boot setup encountered an error")
    }
}

#[cfg(target_os = "windows")]
fn run_on_boot_windows(interval: &u32) -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    // Path to the startup folder
    let startup_path = format!(
        r"{}\Microsoft\Windows\Start Menu\Programs\Startup\{}.lnk",
        env::var("APPDATA")?,
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
fn run_on_boot_linux(interval: &u32) -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let exe_path = exe_path.to_string_lossy();

    let autostart_dir = dirs::config_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Config directory not found"))
        .expect("Error occured")
        .join("autostart");

    std::fs::create_dir_all(&autostart_dir).expect("Couldn't create directory");

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
fn setup_registry() {
    use registry::RegistryHandler;

    if registry::registry(
        get_config_path(CONFIG_DIR, LOGO).to_str().unwrap(),
        APP_NAME,
        &RegistryHandler::new(RegKey::predef(HKEY_CURRENT_USER)),
    )
    .is_ok()
    {
        info!("Registry succesfully setup.");
    } else {
        error!("Registry setup was unsuccesful");
    }
}

async fn download_logo() {
    let logo_path = get_config_path(CONFIG_DIR, LOGO);

    if logo_path.exists() {
        return;
    }

    let logo_url = "https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/logo.png";

    if let Some(parent) = logo_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create log directory");
    }
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&logo_path)
        .unwrap();

    let response = reqwest::get(logo_url)
        .await
        .expect("Request did not succeed. Try again later.");

    info!("Downloading logo.");

    std::fs::write(
        &logo_path,
        response
            .bytes()
            .await
            .expect("Error occured while downloading image bytes"),
    )
    .expect("Could not write to file.");

    info!("Writing logo to file");
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

        let path = get_config_path(CONFIG_DIR, PID_FILE);

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

        assert!(is_first_setup(mock_home_dir_fn)); // `.tuenroll` not yet created

        let config_path = home.path().to_owned().join(CONFIG_DIR);
        fs::create_dir_all(&config_path).unwrap();

        assert!(!is_first_setup(mock_home_dir_fn)); // `.tuenroll` now exists
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
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            store_last_check_time(mock_get_config_path);
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
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            store_last_check_time(mock_get_config_path);

            let result = get_last_check_time(mock_get_config_path);

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
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            // write to file
            let mock_pid = Pid { pid: Some(1234) };
            let pid_file_path = temp_dir.path().join(PID_FILE);
            let pid_data = serde_json::to_string(&mock_pid).unwrap();
            fs::write(pid_file_path, pid_data).unwrap();

            let result = get_stored_pid(mock_get_config_path);
            assert_eq!(result, Some(1234));
        }

        #[test]
        fn test_get_stored_pid_no_pid_file() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            let result = get_stored_pid(mock_get_config_path);

            assert_eq!(result, None);
        }

        #[test]
        fn test_store_pid() {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let mock_get_config_path =
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            store_pid(Some(1234), mock_get_config_path);

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
                |_config_dir: &str, filename: &str| temp_dir.path().join(filename);

            store_pid(None, mock_get_config_path);

            let pid_file_path = temp_dir.path().join(PID_FILE);
            assert!(pid_file_path.exists()); // verify file was created

            let content = fs::read_to_string(pid_file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert!(parsed["pid"].is_null());
        }
    }
}
