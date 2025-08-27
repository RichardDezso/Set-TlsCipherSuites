# Set-TlsCipherSuites

A PowerShell script to manage Windows SCHANNEL cipher suite ordering.  
It supports viewing the current suite list, backing up to JSON, applying a new ordered list, and restoring from backup.  

## Features
- Get current cipher suite order
- Backup and restore configuration
- Apply secure suite lists with correct `REG_MULTI_SZ` format
- Supports `-WhatIf` and `-Confirm` for safe testing

## Requirements
- Windows Server 2019 (TLS 1.2 focus; TLS 1.3 not supported here)
- Run as **Administrator**
- Reboot required for changes to take effect

## Usage
```powershell
# View current suites
.\Set-TlsCipherSuites.ps1 -Mode Get

# Apply a secure ordered list
.\Set-TlsCipherSuites.ps1 -Mode Set -Suites @('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')

# Restore from a backup
.\Set-TlsCipherSuites.ps1 -Mode Restore -From "C:\ProgramData\TlsToggle\cipher-backup-2025-08-27T150101.json"

⚠️ Disclaimer: Test changes in a non-production environment first. Weak cipher suites can break compatibility or reduce security.
