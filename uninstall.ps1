# cipher-shield Windows uninstaller
# Usage: irm https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/uninstall.ps1 | iex

$ErrorActionPreference = "SilentlyContinue"

$InstallDir = Join-Path $env:LOCALAPPDATA "cipher-shield\bin"
$ConfigDir  = Join-Path $env:USERPROFILE ".cipher-shield"
$BinaryPath = Join-Path $InstallDir "cipher-shield.exe"

Write-Host "-> Stopping cipher-shield proxy..."
if (Test-Path $BinaryPath) {
    & $BinaryPath proxy stop 2>$null
}

Write-Host "-> Restoring npm and pip config..."
$NpmOrig = Join-Path $ConfigDir "npm_registry.orig"
if (Test-Path $NpmOrig) {
    $OrigRegistry = Get-Content $NpmOrig -Raw
    if ($OrigRegistry) {
        npm config set registry $OrigRegistry.Trim() 2>$null
        Write-Host "+ npm registry restored"
    }
}
$PipOrig = Join-Path $ConfigDir "pip_index.orig"
$PipConf = Join-Path $env:APPDATA "pip\pip.ini"
if (Test-Path $PipOrig) {
    $OrigIndex = (Get-Content $PipOrig -Raw).Trim()
    if ($OrigIndex -and $OrigIndex -ne "https://pypi.org/simple/") {
        "[global]`nindex-url = $OrigIndex`n" | Set-Content $PipConf -Encoding UTF8
    } else {
        Remove-Item -Force $PipConf -ErrorAction SilentlyContinue
    }
    Write-Host "+ pip index-url restored"
}

Write-Host "-> Removing binary and config..."
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue

# Remove from user PATH
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -like "*$InstallDir*") {
    $NewPath = ($UserPath -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    Write-Host "+ Removed from PATH"
}

Remove-Item -Recurse -Force $ConfigDir -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "cipher-shield uninstalled."
