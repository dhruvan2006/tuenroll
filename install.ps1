# Define constants
$ReleaseUrl = "https://github.com/dhruvan2006/tuenroll/releases/latest/download"
$BinaryName = "tuenroll.exe"
$InstallDir = "$env:USERPROFILE\AppData\Local\tuenroll"

# Detect architecture
$Arch = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemType
Switch ($Arch)
{
    "x64-based PC" {
        $FileSuffix = "x86_64-pc-windows-msvc.exe"
    }
    Default {
        Write-Error "Unsupported architecture: $Arch"; Exit 1
    }
}

# Construct download URL
$DownloadUrl = "$ReleaseUrl/tuenroll-$FileSuffix"

# Download the binary
Write-Host "Downloading $BinaryName for Windows $Arch..."
$BinaryPath = Join-Path -Path $env:TEMP -ChildPath $BinaryName
Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath -ErrorAction Stop

# Check if download was successful
if (-not (Test-Path $BinaryPath))
{
    Write-Error "Download failed. File not found at $BinaryPath."
    Exit 1
}

# Create install directory if it doesn't exist
if (!(Test-Path -Path $InstallDir))
{
    Write-Host "Creating installation directory: $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Check if file already exists in the target directory, and remove if necessary
$ExistingFile = Join-Path -Path $InstallDir -ChildPath $BinaryName
if (Test-Path $ExistingFile)
{
    Write-Host "Existing $BinaryName found. Removing it..."
    Remove-Item $ExistingFile -Force
}

# Move the binary to the install directory
Write-Host "Installing $BinaryName to $InstallDir..."
Move-Item -Path $BinaryPath -Destination $ExistingFile -Force

# Add install directory to user PATH if it's not already there
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($CurrentPath -split ';' | ForEach-Object { $_ -eq $InstallDir }))
{
    Write-Host "Adding $InstallDir to user PATH..."
    $NewPath = $CurrentPath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")

    # Refresh current session's PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
}

# Verify the installation by checking if the command works
Write-Host "Verifying installation..."
if (Get-Command "$InstallDir\$BinaryName" -ErrorAction SilentlyContinue)
{
    Write-Host "$BinaryName has been successfully installed and added to PATH!"
}
else
{
    Write-Error "Installation failed! $BinaryName not found in $InstallDir."
    Exit 1
}
