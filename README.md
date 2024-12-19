# TUEnroll

A CLI tool that automatically registers you for TU Delft exams. It:
- Registers for all exams in your enrolled courses
- Stores credentials securely on your computer
- Sends notifications when registration is successful

<p align="center">
  <img src="logo_full.png" alt="TUEnroll Logo" />
</p>

<p align="center">
  <a href="https://github.com/dhruvan2006/tuenroll/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/dhruvan2006/tuenroll/rust.yml?branch=main&label=Build&logo=github&logoColor=white&color=blue" alt="Build Status" />
  </a>
  <a href="https://codecov.io/gh/dhruvan2006/tuenroll"> 
    <img src="https://codecov.io/gh/dhruvan2006/tuenroll/graph/badge.svg?token=NE7S0F73RL"/> 
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" />
  </a>
  <a href="https://github.com/dhruvan2006/tuenroll/releases">
    <img src="https://img.shields.io/github/v/release/dhruvan2006/tuenroll?logo=github&color=green" alt="Version" />
  </a>
</p>

# 💻 Installation

## ⚡ Quick Install (Recommended)

### 🪟 Windows

```bash
powershell -c "irm https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.ps1 | iex"
```

### 🐧 Linux
#### Ubuntu/Debian:
```bash
sudo apt install libdbus-1-dev pkg-config
curl -fsSL https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.sh | sh
```

#### Fedora:
```bash
sudo dnf install dbus-devel pkgconf-pkg-config
curl -fsSL https://raw.githubusercontent.com/dhruvan2006/tuenroll/main/install.sh | sh
```

### 🍎 macOS
🚧 macOS support is under development

## 🛠️ Alternative methods

### 📦 Using Cargo
If you have Rust installed:
```bash
cargo install tuenroll
```


### 🔧 From Source

```bash
git clone https://github.com/dhruvan2006/tuenroll.git
cd tuenroll
cargo install --path .
```

## ♻️ Usage

### 🚀 Start background service:
It sets up periodic checks to register for exams.
```bash
tuenroll start
```

<p align="center">
  <img src="start.png" alt="TUEnroll Logo" />
</p>

### 🔨 Other commands:
1. Run a one time check:

```bash
tuenroll run
```

2. Stop Background Service:

```bash
tuenroll stop
```

3. Change credentials:

```bash
tuenroll change
```

4. Delete Credentials:

```bash
tuenroll delete
```

5. View Status:

```bash
tuenroll status
```

6. View Logs:

```bash
tuenroll log
```

## Disclaimer

This tool is not officially affiliated with TU Delft. Use it responsibly and at your own risk.
