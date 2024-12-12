#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(target_os = "windows")]
pub fn registry(logo_path: &str, app_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Define variables for the registry entry
    let aumid = app_name;
    let display_name = app_name;
    let icon_uri = logo_path;

    // Open the registry key (or create it if it doesn't exist)
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (app_user_model_id_key, _disp) = hkcu
        .create_subkey(format!("Software\\Classes\\AppUserModelId\\{}", aumid))
        .expect("Could not write to registry");

    // Set registry values
    app_user_model_id_key
        .set_value("DisplayName", &display_name)
        .expect("Could not write DisplayName to registry");
    app_user_model_id_key
        .set_value("IconUri", &icon_uri)
        .expect("Could not write IconUri to registry");

    Ok(())
}
