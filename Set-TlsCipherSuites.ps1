<#
.SYNOPSIS
    Manage SCHANNEL cipher suite ordering on Windows.

.DESCRIPTION
    Allows you to view the current cipher suite list, back it up to JSON, 
    set a new ordered list, or restore from backup. Uses the correct 
    REG_MULTI_SZ format and targets the Local SCHANNEL key so changes 
    apply without a GPO. Supports -WhatIf/-Confirm for safe testing.

.PARAMETER Mode
    Operation to perform: Get, Set, or Restore.

.PARAMETER Suites
    Array of cipher suites in the desired order (only valid with -Mode Set).

.PARAMETER BackupPath
    Directory to store or read backups (defaults to ProgramData\TlsToggle).

.PARAMETER From
    Path to a backup JSON file when restoring.

.EXAMPLE
    .\Set-TlsCipherSuites.ps1 -Mode Get

.EXAMPLE
    $suites = @(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    )
    .\Set-TlsCipherSuites.ps1 -Mode Set -Suites $suites

.EXAMPLE
    .\Set-TlsCipherSuites.ps1 -Mode Restore -From 'C:\ProgramData\TlsToggle\cipher-backup.json'

.NOTES
    Run as Administrator.
    Reboot required for changes to take effect.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [ValidateSet('Get','Set','Restore')]
    [string]$Mode = 'Get',

    [string[]]$Suites,

    [string]$BackupPath = "$env:ProgramData\TlsToggle",

    [string]$From
)

# --- Functions ---

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script as Administrator."
    }
}

$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$Value = "Functions"

function Ensure-Key($path) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

function Get-CipherSuites {
    (Get-ItemProperty -Path $Key -Name $Value -ErrorAction SilentlyContinue).$Value
}

function Backup-CipherSuites {
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath | Out-Null
    }
    $file = Join-Path $BackupPath ("cipher-backup-{0}.json" -f (Get-Date -Format "yyyy-MM-ddTHHmmss"))
    $payload = [pscustomobject]@{
        Path   = $Key
        Name   = $Value
        Suites = @(Get-CipherSuites)
    }
    $payload | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
    Write-Host "Backup saved: $file"
    return $file
}

function Set-CipherSuites([string[]]$list) {
    if (-not $list -or $list.Count -eq 0) {
        throw "No suites provided. Use -Suites with -Mode Set."
    }
    Ensure-Key $Key
    if ($PSCmdlet.ShouldProcess($Key, "Set cipher suite order (count=$($list.Count))")) {
        New-ItemProperty -Path $Key -Name $Value -PropertyType MultiString -Value $list -Force | Out-Null
    }
    Write-Host "Cipher suite order updated. Reboot required."
}

function Restore-CipherSuites([string]$file) {
    if (-not (Test-Path $file)) {
        throw "Backup file not found: $file"
    }
    $data = Get-Content -Raw -Path $file | ConvertFrom-Json
    if ($PSCmdlet.ShouldProcess($Key, "Restore cipher suites from backup")) {
        Ensure-Key $Key
        New-ItemProperty -Path $Key -Name $Value -PropertyType MultiString -Value $data.Suites -Force | Out-Null
    }
    Write-Host "Cipher suites restored from backup. Reboot required."
}

# --- Main ---

Test-Admin

switch ($Mode) {
    'Get' {
        $suites = Get-CipherSuites
        if ($suites) {
            Write-Host "`nCurrent Cipher Suites (first 10 shown):"
            $suites | Select-Object -First 10 | ForEach-Object { "  $_" }
            if ($suites.Count -gt 10) {
                Write-Host "... ($($suites.Count) total)"
            }
        } else {
            Write-Warning "No cipher suites configured at $Key"
        }
    }

    'Set' {
        Backup-CipherSuites | Out-Null
        Set-CipherSuites -list $Suites
    }

    'Restore' {
        if (-not $From) { throw "Use -From <backup.json> with -Mode Restore" }
        Restore-CipherSuites -file $From
    }
}
