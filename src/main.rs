mod api;
mod creds;
mod models;
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
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
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
    /// Change username and password
    Change,
    /// Delete any saved credentials
    Delete,
}

// TODO: Give a finalized name for the directory
const APP_NAME: &str = "tuenroll";
const CONFIG_DIR: &str = ".tuenroll";
const CONFIG_FILE: &str = "config.json";
const PID_FILE: &str = "process.json";
const LOG_FILE: &str = "tuenroll.log";

#[tokio::main]
async fn main() {
    set_up_logging();

    let cli = Cli::parse();

    let manager = CredentialManager::new(get_config_path(CONFIG_DIR, CONFIG_FILE));

    match &cli.command {
        Commands::Run => {
            info!("Starting the 'Run' command execution.");
            let credentials = get_credentials(&manager, false).await;
            match run_auto_sign_up(false, &credentials).await {
                Ok(()) => println!("{}", "Success: Exam check ran.".green().bold()),
                Err(()) => println!("{}", "Failure: A network error occured".red().bold()),
            }
        }
        Commands::Start { interval, boot } => {
            info!("Starting the 'Start' command execution.");

            let credentials = get_credentials(&manager, true).await;

            // WARNING: Do not have any print statements or the the command and process will stop working detached
            if env::var("DAEMONIZED").err().is_some() {
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
                run_loop(interval, credentials).await;
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
        Commands::Change => {
            info!("Changing credentials.");
            match manager.change_credentials().await {
                Ok(_) => println!("{}", "Success: Credentials changed!".green().bold()),
                Err(_) => println!("{}", "Failed: A network problem occured.".red().bold()),
            }
        }
        Commands::Delete => {
            info!("Deleting credentials.");
            manager.delete_credentials();
            println!("{}", "Success: Credentials deleted!".green().bold());
        }
    }
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

    info!("Initialized the logger");
}

async fn run_loop(interval: &u32, credentials: Credentials) {
    let _ = run_auto_sign_up(true, &credentials).await;

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
            let _ = run_auto_sign_up(true, &credentials).await;
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

async fn get_credentials(manager: &CredentialManager, is_loop: bool) -> Credentials {
    let credentials;

    loop {
        let request = manager.get_valid_credentials();
        if let Some(data) = handle_request(is_loop, request.await) {
            credentials = data;
            break;
        }
    }

    credentials
}

/// Runs the auto signup fully o nce
/// Gets the credentials, the access token
/// Automatically signs up for all the tests
/// Prints the result of execution
async fn run_auto_sign_up(is_loop: bool, credentials: &Credentials) -> Result<(), ()> {
    info!("Fetching credentials from config file.");

    let access_token = credentials
        .access_token
        .clone()
        .expect("Access token should be present");
    let registration_result;
    let api = Api::new();
    loop {
        let request = api.register_for_tests(
            &access_token,
            api::REGISTERED_COURSE_URL,
            api::TEST_COURSE_URL,
            api::TEST_REGISTRATION_URL,
        );
        if let Some(data) = handle_request(is_loop, request.await) {
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
            show_notification(&course_name);
        }
    }
    Ok(())
}

fn show_notification(course_name: &str) {
    Notification::new()
        .summary("Exam Registration Success")
        .body(&format!(
            "You have been successfully registered for the exam: {}",
            course_name
        ))
        .icon("info")
        .show()
        .unwrap();
}

fn handle_request<R, E: ToString>(is_loop: bool, request: Result<R, E>) -> Option<R> {
    match request {
        Ok(data) => Some(data),
        Err(e) => {
            if !is_loop {
                panic!("{}", "A network error likely occured".red().bold());
            }
            // Logs the error and wait 5 seconds before continuing
            error!("{}", e.to_string());
            thread::sleep(time::Duration::from_secs(5));
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

    #[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Set up a temporary directory as `HOME` to test whether `get_config_path()`
    /// returns the accurate path
    #[test]
    #[cfg(target_family = "unix")]
    fn test_get_config_path() {
        let temp_home = tempdir().expect("Failed to create temp directory");
        env::set_var("HOME", &temp_home.path());

        let config_path = get_config_path(CONFIG_DIR, CONFIG_FILE);

        let expected_path = temp_home.path().join(CONFIG_DIR).join(CONFIG_FILE);
        assert_eq!(expected_path, config_path);
    }
}
