use std::error::Error;
use winreg::enums::*;
use winreg::RegKey;

pub trait RegistryHandlerTrait {
    fn create_subkey(&self, path: &str) -> Result<(), Box<dyn Error>>;
    fn set_value(&self, path: &str, key: &str, value: &str) -> Result<(), Box<dyn Error>>;
}

pub struct RegistryHandler {
    hkcu: RegKey,
}

impl RegistryHandler {
    pub fn new(hkcu: RegKey) -> Self {
        Self { hkcu }
    }
}

impl RegistryHandlerTrait for RegistryHandler {
    fn create_subkey(&self, path: &str) -> Result<(), Box<dyn Error>> {
        self.hkcu.create_subkey(path)?;
        Ok(())
    }

    fn set_value(&self, path: &str, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let subkey = self.hkcu.open_subkey_with_flags(path, KEY_WRITE)?;
        subkey.set_value(key, &value)?;
        Ok(())
    }
}

pub fn registry(
    logo_path: &str,
    app_name: &str,
    handler: &impl RegistryHandlerTrait,
) -> Result<(), Box<dyn Error>> {
    // Define variables for the registry entry
    let aumid = app_name;
    let display_name = app_name;
    let icon_uri = logo_path;
    let path = format!("Software\\Classes\\AppUserModelId\\{}", aumid);

    // Open the registry key (or create it if it doesn't exist)
    handler.create_subkey(&path)?;

    // Set registry values
    handler.set_value(&path, "DisplayName", display_name)?;
    handler.set_value(&path, "IconUri", icon_uri)?;

    Ok(())
}

#[allow(dead_code)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::sync::Mutex;

    use super::*;

    struct MockRegistryHandler {
        data: Mutex<HashMap<String, HashMap<String, String>>>,
    }

    impl MockRegistryHandler {
        pub fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl RegistryHandlerTrait for MockRegistryHandler {
        fn create_subkey(&self, path: &str) -> Result<(), Box<dyn Error>> {
            let mut data = self.data.lock().unwrap();
            data.entry(path.to_string()).or_default();
            Ok(())
        }

        fn set_value(&self, path: &str, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
            let mut data = self.data.lock().unwrap();
            //let mut data = data.entry(path)
            let map = data.get_mut(path).unwrap();

            map.insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    #[test]
    fn test_registry_with_mock() {
        let mock_handler = MockRegistryHandler::new();

        let logo_path = "C:\\Path\\To\\Logo.ico";
        let app_name = "TestApp";

        let result = registry(logo_path, app_name, &mock_handler);
        assert!(result.is_ok());

        let data = mock_handler.data.lock().unwrap();
        let subkey = data.get("Software\\Classes\\AppUserModelId\\TestApp");
        assert!(subkey.is_some());

        let values = subkey.unwrap();
        assert_eq!(values.get("DisplayName"), Some(&app_name.to_string()));
        assert_eq!(values.get("IconUri"), Some(&logo_path.to_string()));
    }
}
