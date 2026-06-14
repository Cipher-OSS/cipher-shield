# cipher-shield Windows installer
# Usage: irm https://raw.githubusercontent.com/homes853/cipher-shield/master/install.ps1 | iex
#
# To include your Anthropic API key:
#   $env:ANTHROPIC_API_KEY = "sk-ant-..."
#   irm https://raw.githubusercontent.com/homes853/cipher-shield/master/install.ps1 | iex

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "cipher-shield\bin"
$ConfigDir  = Join-Path $env:USERPROFILE ".cipher-shield"
$Binary     = "cipher-shield.exe"

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Error "cipher-shield requires a 64-bit system."
    exit 1
}

$BaseUrl     = "https://github.com/homes853/cipher-shield/releases/latest/download"
$DownloadUrl = "$BaseUrl/cipher-shield-windows-amd64.exe"

Write-Host "-> Installing cipher-shield (windows/amd64)..."

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir  | Out-Null

$TmpFile = [System.IO.Path]::GetTempFileName() + ".exe"
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpFile -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}
Move-Item -Force $TmpFile (Join-Path $InstallDir $Binary)
Write-Host "+ Binary installed to $InstallDir\$Binary"

# Add to user PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
    Write-Host "+ Added $InstallDir to user PATH"
    Write-Host "  (Restart your terminal for PATH changes to take effect)"
}

# Save API key if provided
if ($env:ANTHROPIC_API_KEY) {
    $EnvFile = Join-Path $ConfigDir "cipher-shield.env"
    "ANTHROPIC_API_KEY=$($env:ANTHROPIC_API_KEY)" | Set-Content $EnvFile -Encoding UTF8
    (Get-Item $EnvFile).Attributes = "Hidden"
    Write-Host "+ API key saved to $EnvFile"
}

Write-Host ""
Write-Host "cipher-shield installed successfully!"
Write-Host ""
Write-Host "  Start proxy:   cipher-shield proxy start"
Write-Host "  Stop proxy:    cipher-shield proxy stop"
Write-Host "  Scan lockfile: cipher-shield scan lockfile package-lock.json"
Write-Host ""
Write-Host "  To enable Claude Opus deep analysis:"
Write-Host "  `$env:ANTHROPIC_API_KEY = 'sk-ant-...'"
Write-Host "  cipher-shield proxy start"
