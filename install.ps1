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
        Write-Host "Unsupported architecture: $Arch" -ForegroundColor Red
        Exit 1
    }
}

# Construct download URL
$DownloadUrl = "$ReleaseUrl/tuenroll-$FileSuffix"

# Download the binary
Write-Host "Downloading $BinaryName for Windows $Arch..." -ForegroundColor Cyan
$BinaryPath = Join-Path -Path $env:TEMP -ChildPath $BinaryName
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath -ErrorAction Stop
}
catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    Exit 1
}

# Check if download was successful
if (-not (Test-Path $BinaryPath))
{
    Write-Host "Download failed. File not found at $BinaryPath." -ForegroundColor Red
    Exit 1
}

# Create install directory if it doesn't exist
if (!(Test-Path -Path $InstallDir))
{
    Write-Host "Creating installation directory: $InstallDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Check if file already exists in the target directory, and remove if necessary
$ExistingFile = Join-Path -Path $InstallDir -ChildPath $BinaryName
if (Test-Path $ExistingFile)
{
    Write-Host "Existing $BinaryName found. Removing it..." -ForegroundColor Cyan
    Remove-Item $ExistingFile -Force
}

# Move the binary to the install directory
Write-Host "Installing $BinaryName to $InstallDir..." -ForegroundColor Cyan
Move-Item -Path $BinaryPath -Destination $ExistingFile -Force

# Add install directory to user PATH if it's not already there
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($CurrentPath -split ';' | Where-Object { $_ -eq $InstallDir }))
{
    Write-Host "Adding $InstallDir to user PATH..." -ForegroundColor Cyan
    $NewPath = $CurrentPath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
}

# Add InstallDir to the PATH
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
        [Environment]::GetEnvironmentVariable("Path", "User") +
        ";$InstallDir"

# More robust verification
Write-Host "Verifying installation..." -ForegroundColor Cyan
try
{
    $process = Start-Process -FilePath "$InstallDir\$BinaryName" -ArgumentList "--version" -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -eq 0)
    {
        Write-Host "$BinaryName has been successfully installed and added to PATH!" -ForegroundColor Green
    }
    else
    {
        Write-Host "Installation verification failed with exit code $( $process.ExitCode )" -ForegroundColor Red
        Exit 1
    }
}
catch
{
    Write-Host "Failed to run $BinaryName. Error: $_" -ForegroundColor Red
    Exit 1
}

# Inform user about terminal reinstallation
Write-Host "!!! IMPORTANT: Please restart your terminal session !!!" -ForegroundColor Magenta