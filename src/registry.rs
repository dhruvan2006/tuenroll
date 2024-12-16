use winreg::RegKey;
use winreg::enums::*;

pub trait RegistryHandlerTrait {
    fn create_subkey(&self, path: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn set_value(&self, path: &str, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>>;
}


pub struct RegistryHandler {
    hkcu: RegKey,
}

impl RegistryHandler {
    pub fn new(hkcu: RegKey) -> Self {
        Self { hkcu}
    }
}

#[cfg(target_os = "windows")]
impl RegistryHandlerTrait for RegistryHandler {
    fn create_subkey(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.hkcu.create_subkey(path)?;
        Ok(())
    }

    fn set_value(&self, path: &str, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let subkey = self.hkcu.open_subkey_with_flags(path, KEY_WRITE)?;
        subkey.set_value(key, &value)?;
        Ok(())
    }
}


pub fn registry(logo_path: &str, app_name: &str, handler: impl RegistryHandlerTrait) -> Result<(), Box<dyn std::error::Error>> {
    // Define variables for the registry entry
    let aumid = app_name;
    let display_name = app_name;
    let icon_uri = logo_path;   
    let path = format!("Software\\Classes\\AppUserModelId\\{}", aumid);

    // Open the registry key (or create it if it doesn't exist)
    handler
        .create_subkey(&path)
        .expect("Could not write to registry");

    // Set registry values
    handler
        .set_value(&path, "DisplayName", &display_name)
        .expect("Could not write DisplayName to registry");
    handler
        .set_value(&path, "IconUri", &icon_uri)
        .expect("Could not write IconUri to registry");

    Ok(())
}



// #[cfg(test, target_os="windows")]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_registry() {
//         RegKey::raw_handle(&self);
//         let hkcu = RegKey::predef(HKEY_CURRENT_USER)
//         registry("/some/path", "app_name", hkcu)
        
//     }
// }
