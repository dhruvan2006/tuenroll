# TUEnroll
TUEnroll is a CLI tool designed to automate exam registrations at TU Delft.

It periodically checks for open exam registrations and automatically registers you when new exams are available.

![TUEnroll Logo](logo.png)

## Installation
Use the package manager `cargo` to install tuenroll.

```bash
cargo install tuenroll
```

Ubuntu:
```bash
sudo apt install libdbus-1-dev pkg-config
```
Fedora:
```bash
sudo dnf install dbus-devel pkgconf-pkg-config
```

## Usage
### 1. Start background service:
```bash
tuenroll start
```

2. Run a one time check:
```bash
tuenroll run
```

3. Stop Background Service:
```bash
tuenroll stop
```

4. Change credentials:
```bash
tuenroll change
```

5. Delete Credentials:
```bash
tuenroll delete
```

## Logging
Logs are stored in `~/.tuenroll/tuenroll.log`. Review these logs for details about the application's operation and debugging information.

## License

## Disclaimer
This tool is not officially affiliated with TU Delft. Use it responsibly and at your own risk.