<#
.SYNOPSIS
    This PowerShell script enabled Explorer Data Execution Prevention, which provides additional protection by performing checks on memory to help prevent malicious code from running

.NOTES
    Author          : Steven Brown
    LinkedIn        : linkedin.com/in/stevenbrown66/
    GitHub          : github.com/stbrown2003
    Date Created    : 2026-10-03
    Last Modified   : 2026-10-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000215

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\>STIG-ID-WN11-CC-000215.ps1 
#>


# ==============================================================================
# STIG Fix: Windows 11 - Enable Data Execution Prevention for Explorer
# Hive:     HKEY_LOCAL_MACHINE
# Path:     SOFTWARE\Policies\Microsoft\Windows\Explorer
# Value:    NoDataExecutionPrevention = 0 (REG_DWORD)
# Note:     This STIG passes if the value is 0 OR if the value does not exist.
#           This script ensures the value is explicitly set to 0 for clarity.
# ==============================================================================

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$ValueName    = "NoDataExecutionPrevention"
$ValueData    = 0
$ValueType    = "DWord"

# Require admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# Create the registry path if it does not exist
if (-not (Test-Path -Path $RegistryPath)) {
    Write-Host "Registry path not found. Creating: $RegistryPath" -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
    Write-Host "Registry path created successfully." -ForegroundColor Green
} else {
    Write-Host "Registry path already exists: $RegistryPath" -ForegroundColor Cyan
}

# Check if the value already exists
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -ne $CurrentValue) {
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "Value '$ValueName' is already set correctly to $ValueData. No changes needed." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Value '$ValueName' exists but is incorrect (Current: $($CurrentValue.$ValueName)). Updating..." -ForegroundColor Yellow
    }
} else {
    Write-Host "Value '$ValueName' not found. Creating with value $ValueData to explicitly satisfy STIG requirement..." -ForegroundColor Yellow
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