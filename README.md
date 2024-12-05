# TUEnroll

**TUEnroll** is a CLI tool designed to automate the exam registration process at **TU Delft**.

It periodically checks for open exam registrations and automatically registers you when new exams are available.

<p align="center">
  <img src="logo.png" alt="TUEnroll Logo" />
</p>

<p align="center">
  <a href="https://github.com/dhruvan2006/tuenroll/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/dhruvan2006/tuenroll/rust.yml?branch=main&label=Build&logo=github&logoColor=white&color=blue" alt="Build Status" />
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" />
  </a>
  <a href="https://github.com/dhruvan2006/tuenroll/releases">
    <img src="https://img.shields.io/github/v/release/dhruvan2006/tuenroll?logo=github&color=green" alt="Version" />
  </a>
  <a href="https://crates.io/crates/tuenroll">
    <img src="https://img.shields.io/crates/d/tuenroll?color=orange&logo=cargo&logoColor=white" alt="Downloads" />
  </a>
  <a href="https://crates.io/crates/tuenroll">
    <img src="https://img.shields.io/crates/v/tuenroll.svg?logo=cargo&logoColor=white" alt="Version" />
  </a>
</p>

## Installation

### With Cargo

Use the package manager `cargo` to install tuenroll.

```bash
cargo install tuenroll
```

### With binaries

#### Windows

```bash
powershell -c "irm https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.ps1 | iex"
```

#### Ubuntu:

```bash
sudo apt install libdbus-1-dev pkg-config
curl -fsSL https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.sh | sh
```

#### Fedora:

```bash
sudo dnf install dbus-devel pkgconf-pkg-config
curl -fsSL https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.sh | sh
```

#### Mac

```bash
curl -fsSL https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.sh | sh
```

### Build from source

```bash
git clone https://github.com/dhruvan2006/tuenroll.git
cd tuenroll
cargo install --path .
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

## License

## Disclaimer

This tool is not officially affiliated with TU Delft. Use it responsibly and at your own risk.
