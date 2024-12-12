mod api;
mod creds;
mod models;
use crate::api::ApiTrait;
use ::time::UtcOffset;
use api::Api;
use clap::{Parser, Subcommand};
use colored::*;
use creds::{CredentialManager, Credentials};
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
use std::process::exit;
#[cfg(target_os = "windows")]
use std::process::Stdio;
use std::{process::Command, thread, time};

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

#[allow(clippy::zombie_processes)]
#[tokio::main]
async fn main() {
    // Check if it's the first setup
    if is_first_setup() {
        display_logo();

        println!("{}", "Welcome to TUEnroll CLI!".bright_cyan());
        println!(
            "{}",
            "Automate your TU Delft exam registrations. Let's get you set up!".bright_cyan()
        );
    }

    set_up_logging();

    let cli = Cli::parse();

    let manager = CredentialManager::new(Api::new(), APP_NAME.to_string());

    match &cli.command {
        Commands::Run => {
            info!("Starting the 'Run' command execution.");
            let _ = get_credentials(&manager, false, false).await;
            match run_auto_sign_up(false, &manager, false).await {
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

            // WARNING: Do not have any print statements or the command and process will stop working detached
            if env::var("DAEMONIZED").err().is_some() {
                let _ = get_credentials(&manager, true, *boot).await;

                // Checks whether a process was running, if not don't run the program
                if *boot && get_stored_pid().is_none() {
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

                store_pid(Some(child.id()));
                //println!("{}", "Success: Service started.".green().bold());
                info!("Daemon process started with PID: {}", child.id());
                if !boot {
                    println!("Command 'Start' was successfully started");
                }
                return;
            } else {
                info!("Daemon process enabled: starting loop");
                run_loop(interval, &manager, *boot).await;
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
            let process_status = if let Some(Some(pid)) = process_is_running().then(get_stored_pid)
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

            let network_status = match check_network_status().await {
                Ok(status) => status.green(),
                Err(_) => "Network check failed.".to_string().red(),
            };

            let last_check_status = match get_last_check_time() {
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
            let _ = get_credentials(&manager, false, false).await;
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

fn is_first_setup() -> bool {
    let config_path = dirs::home_dir()
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

async fn check_network_status() -> Result<String, Box<dyn std::error::Error>> {
    match reqwest::get("https://my.tudelft.nl/").await {
        Ok(_) => Ok("Network is up.".to_string()),
        Err(_) => Ok("Network is down.".to_string()),
    }
}

fn store_last_check_time() {
    let last_check_time = chrono::Utc::now().to_rfc3339();
    let path = get_config_path(CONFIG_DIR, LAST_CHECK_FILE);
    let data = serde_json::json!({ "last_check": last_check_time });

    match std::fs::write(path, serde_json::to_string(&data).unwrap()) {
        Ok(_) => info!("Last check time saved."),
        Err(e) => error!("Failed to save last check time: {}", e),
    }
}

fn get_last_check_time() -> Option<String> {
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

// Helper function to calculate time difference
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
                    show_notification("Your credentials are invalid. Run tuenroll start again");
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

fn get_stored_pid() -> Option<u32> {
    if let Ok(pid) = std::fs::read_to_string(get_config_path(CONFIG_DIR, PID_FILE)) {
        if let Ok(pid) = serde_json::from_str::<Pid>(&pid) {
            return pid.pid;
        }
    }
    None
}

fn stop_program() -> Option<u32> {
    let pid = get_stored_pid();
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
    store_pid(None);
    Some(pid)
}

fn process_is_running() -> bool {
    let stored_pid = get_stored_pid();
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
            store_pid(None);
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
            store_pid(None);
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
            ));
        }
    }

    // Store the last check time
    store_last_check_time();

    Ok(())
}

fn show_notification(body: &str) {
    if let Err(e) = Notification::new()
        .summary("TUEnroll")
        .body(body)
        .icon("info")
        .timeout(5 * 1000) // 5 seconds
        .show()
    {
        error!("Failed to show notification: {}", e);
    }
}

fn handle_request<R, E: ToString>(
    is_loop: bool,
    request: Result<R, E>,
    is_boot: bool,
) -> Option<R> {
    match request {
        Ok(data) => Some(data),
        Err(e) => {
            // Logs the error and wait 5 seconds before continuing
            if !is_boot {
                eprintln!("{}", e.to_string().red().bold());
            }
            error!("{}", e.to_string());

            if e.to_string() != "Invalid credentials" {
                if !is_loop {
                    exit(0); // Exit if `run` and no internet connection
                }
                thread::sleep(time::Duration::from_secs(5));
            }
            None
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
