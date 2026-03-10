<#
.SYNOPSIS
    This PowerShell script disables the display of slide shows on the lock screen.

.NOTES
    Author          : Steven Brown
    LinkedIn        : linkedin.com/in/stevenbrown66/
    GitHub          : github.com/stbrown2003
    Date Created    : 2026-10-03
    Last Modified   : 2026-10-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\>STIG-ID-WN11-CC-000010.ps1 
#>

# ==============================================================================
# STIG Fix: Windows 11 - Disable Lock Screen Slideshow
# Hive:     HKEY_LOCAL_MACHINE
# Path:     SOFTWARE\Policies\Microsoft\Windows\Personalization
# Value:    NoLockScreenSlideshow = 1 (REG_DWORD)
# ==============================================================================

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$ValueName    = "NoLockScreenSlideshow"
$ValueData    = 1
$ValueType    = "DWord"


# Create the registry path if it does not exist
if (-not (Test-Path -Path $RegistryPath)) {
    Write-Host "Registry path not found. Creating: $RegistryPath" -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
    Write-Host "Registry path created successfully." -ForegroundColor Green
} else {
    Write-Host "Registry path already exists: $RegistryPath" -ForegroundColor Cyan
}

# Check if the value already exists and is correct
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -ne $CurrentValue) {
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "Value '$ValueName' is already set correctly to $ValueData. No changes needed." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Value '$ValueName' exists but is incorrect (Current: $($CurrentValue.$ValueName)). Updating..." -ForegroundColor Yellow
    }
} else {
    Write-Host "Value '$ValueName' not found. Creating..." -ForegroundColor Yellow
}

# Set the registry value
Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
Write-Host "Value '$ValueName' set to $ValueData successfully." -ForegroundColor Green

# Verify the change
$Verify = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
if ($Verify.$ValueName -eq $ValueData) {
    Write-Host "Verification passed. STIG setting applied correctly." -ForegroundColor Green
} else {
    Write-Error "Verification FAILED. Please check the registry manually."
    exit 1
}