# Windows EPS Data Collection Tool

> **Get-WindowsEPS.ps1** — Scan Windows Event Logs to calculate Events Per Second (EPS) and projected data volume for SIEM sizing and capacity planning.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Local Host Scan](#local-host-scan)
  - [IP List Scan](#ip-list-scan)
  - [Domain Scan](#domain-scan)
  - [Advanced Examples](#advanced-examples)
- [Parameters](#parameters)
- [Output Files](#output-files)
  - [Detailed Report Columns](#detailed-report-columns)
  - [Summary Report Columns](#summary-report-columns)
  - [Sample Output](#sample-output)
- [Data Volume Calculation](#data-volume-calculation)
- [WinCollect Profile Mapping](#wincollect-profile-mapping)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

The Windows EPS Data Collection Tool scans Windows Event Logs (Application, Security, System, and optionally ForwardedEvents and Sysmon) to calculate:

- **Average EPS** — Events Per Second based on historical log data
- **Peak EPS Estimate** — 3× average as a capacity planning buffer
- **Data Volume Projections** — Estimated GB per Day, Week, Month, and Year
- **WinCollect Profile Suggestion** — Recommended agent profile based on EPS thresholds

It supports three scan modes: local host, remote hosts via IP list, and Active Directory domain-wide discovery.

---

## Key Features

- **Three scan modes** — Local, IP list file, or full AD domain discovery
- **Extended log sources** — Application, Security, System + optional ForwardedEvents and Sysmon
- **Data volume projections** — GB/Day, GB/Week, GB/Month, GB/Year per log and total
- **Average event size calculation** — Derived from log file size ÷ event count
- **Peak EPS estimation** — 3× multiplier for SIEM capacity planning
- **WinCollect profile mapping** — Automatic tier classification with threshold warnings
- **Dual CSV output** — Detailed per-log report + high-level summary
- **Persistent logging** — Timestamped log file for audit and troubleshooting
- **Graceful failure handling** — Continues scanning remaining hosts on per-host errors
- **CLI and interactive modes** — Full parameter support with interactive fallback
- **WinRM + ICMP validation** — Connectivity checks before scanning remote hosts

---

## Prerequisites

| Requirement | Details | How to Check / Install |
|---|---|---|
| **PowerShell** | Version 5.1 or later | `$PSVersionTable.PSVersion` |
| **Execution Policy** | `RemoteSigned` or `Bypass` | `Get-ExecutionPolicy` |
| **Admin Privileges** | Run as Administrator | Required for Security log access |
| **RSAT AD Module** | Domain scan mode only | `Get-Module -ListAvailable ActiveDirectory` |
| **WinRM** | Remote scanning | `Test-WSMan -ComputerName <target>` |
| **Network Access** | TCP 5985/5986 + ICMP | Firewall rules for WinRM and ping |

---

## Installation

**1. Download the script**

```powershell
# Clone the repository
git clone https://github.com/your-org/windows-eps-tool.git
cd windows-eps-tool

# Or download directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-org/windows-eps-tool/main/Get-WindowsEPS.ps1" -OutFile "Get-WindowsEPS.ps1"
```

**2. Set execution policy**

```powershell
# Permanent (recommended)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or single session only
Set-ExecutionPolicy Bypass -Scope Process
```

**3. Enable WinRM on remote targets** (if scanning remote hosts)

```powershell
# On each target host (or deploy via GPO)
Enable-PSRemoting -Force

# Trust specific hosts (on the scanning machine)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.*" -Force
```

---

## Usage

### Interactive Mode

Run the script without parameters to be guided through the process:

```powershell
.\Get-WindowsEPS.ps1
```

You'll see a menu to select the scan mode, followed by prompts for any required inputs.

```
========================================
  Windows EPS Data Collection Tool v2.0.0
========================================

Select scan mode:
  [1] Local Host  - Scan this computer only
  [2] IP List     - Scan hosts from a file
  [3] Domain      - Scan all domain computers
```

### Local Host Scan

Scans event logs on the machine where the script is executed. No credentials required.

```powershell
.\Get-WindowsEPS.ps1 -Mode LocalHost
```

### IP List Scan

Scans remote computers listed in a text file (one hostname or IP per line).

```powershell
.\Get-WindowsEPS.ps1 -Mode IPList -InputFile "C:\hosts.txt"
```

**Example `hosts.txt`:**

```text
# Domain Controllers
dc01.corp.local
dc02.corp.local

# File Servers
192.168.1.50
192.168.1.51

# Exchange
exchange01.corp.local
```

> Lines starting with `#` are treated as comments and ignored. Blank lines are skipped.

### Domain Scan

Automatically discovers all enabled Windows computers in Active Directory.

```powershell
.\Get-WindowsEPS.ps1 -Mode Domain
```

### Advanced Examples

```powershell
# Local scan with ForwardedEvents and Sysmon logs
.\Get-WindowsEPS.ps1 -Mode LocalHost -IncludeForwardedEvents -IncludeSysmon

# IP list with custom output directory
.\Get-WindowsEPS.ps1 -Mode IPList -InputFile "servers.txt" -OutputPath "D:\EPSReports"

# Domain scan with pre-supplied credentials (useful for automation)
$cred = Get-Credential
.\Get-WindowsEPS.ps1 -Mode Domain -Credential $cred -OutputPath "C:\Reports"

# Scan only Security and Sysmon logs
.\Get-WindowsEPS.ps1 -Mode LocalHost -LogNames @('Security') -IncludeSysmon

# Full scan with all options
.\Get-WindowsEPS.ps1 -Mode IPList `
    -InputFile "C:\all-servers.txt" `
    -OutputPath "C:\EPSReports" `
    -IncludeForwardedEvents `
    -IncludeSysmon `
    -TimeoutSeconds 60
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Mode` | `String` | *(interactive)* | Scan mode: `LocalHost`, `IPList`, or `Domain` |
| `-InputFile` | `String` | *(file dialog)* | Path to text file with hostnames/IPs (IPList mode) |
| `-OutputPath` | `String` | Desktop | Directory for output CSV reports and log file |
| `-LogNames` | `String[]` | `Application, Security, System` | Event log names to scan |
| `-Credential` | `PSCredential` | *(prompt)* | Credentials for remote host access |
| `-IncludeForwardedEvents` | `Switch` | `$false` | Also scan the ForwardedEvents log |
| `-IncludeSysmon` | `Switch` | `$false` | Also scan Microsoft-Windows-Sysmon/Operational |
| `-TimeoutSeconds` | `Int` | `30` | Connection timeout for remote hosts |
| `-MaxConcurrentJobs` | `Int` | `5` | Maximum parallel scan jobs |

---

## Output Files

The script generates three files in the output directory:

| File | Description |
|---|---|
| `EPS-Report-<timestamp>.csv` | Detailed per-log metrics for every computer |
| `EPS-Summary-<timestamp>.csv` | High-level summary with totals and profiles |
| `EPS-Collection-Log-<timestamp>.txt` | Timestamped execution log for troubleshooting |

### Detailed Report Columns

For **each log** scanned (Application, Security, System, etc.), the report includes:

| Column | Description |
|---|---|
| `<Log> EPS` | Average events per second |
| `<Log> Peak Est.` | Estimated peak EPS (3× average) |
| `<Log> Total Events` | Total event count in the log |
| `<Log> Size (MB)` | Current log file size |
| `<Log> Avg Event (KB)` | Average size per event (log size ÷ event count) |
| `<Log> GB/Day` | Projected data volume per day |
| `<Log> GB/Week` | Projected data volume per week |
| `<Log> GB/Month` | Projected data volume per month (30 days) |
| `<Log> GB/Year` | Projected data volume per year (365 days) |
| `<Log> Oldest Event` | Timestamp of the earliest event |
| `<Log> Newest Event` | Timestamp of the most recent event |
| `<Log> Time Span (h)` | Hours between oldest and newest events |
| `<Log> Status` | `OK`, `Empty`, or `Error` |

**Total columns** across all logs:

| Column | Description |
|---|---|
| `Total EPS` | Combined EPS across all scanned logs |
| `Peak Estimate EPS` | Combined peak estimate (3× total average) |
| `Total GB/Day` | Combined projected volume per day |
| `Total GB/Week` | Combined projected volume per week |
| `Total GB/Month` | Combined projected volume per month |
| `Total GB/Year` | Combined projected volume per year |
| `Profile Suggestion` | Recommended WinCollect agent profile |
| `Profile Range` | EPS range for the suggested profile |
| `Profile Note` | Warnings (e.g., if EPS exceeds standard profiles) |

### Summary Report Columns

| Column | Description |
|---|---|
| `Computer` | Hostname or IP |
| `OS Version` | Windows OS version |
| `Total EPS` | Combined EPS |
| `Peak Estimate EPS` | Combined peak estimate |
| `Total GB/Day` | Total projected GB per day |
| `Total GB/Week` | Total projected GB per week |
| `Total GB/Month` | Total projected GB per month |
| `Total GB/Year` | Total projected GB per year |
| `Profile Suggestion` | Recommended profile |
| `Profile Range` | EPS range |
| `Profile Note` | Warnings |

### Sample Output

**Console summary after a scan:**

```
==================== EPS SCAN SUMMARY ====================

Computer       OS                                   Total EPS  GB/Day  GB/Week  GB/Month  GB/Year  Profile
--------       --                                   ---------  ------  -------  --------  -------  -------
VM-DC-01       Microsoft Windows Server 2022 Std    0.15420    0.0087  0.0612   0.2628    3.1974   Default Endpoint
VM-EXCH-01     Microsoft Windows Server 2022 Std    85.32100   4.8200  33.7400  144.8571  1762.43  Typical Server
VM-WKS-01      Microsoft Windows 11 Enterprise      0.05242    0.0031  0.0217   0.0930    1.1315   Default Endpoint

  Total Aggregate EPS:    85.52762
  Estimated Data Volume:  4.8318 GB/Day | 33.8229 GB/Week | 145.2129 GB/Month | 1766.76 GB/Year
  Computers Scanned:      3
  Connection Failures:    0
  Connection Issues:      0

=========================================================
```

---

## Data Volume Calculation

The script estimates storage requirements using the following methodology:

```
Average Event Size (KB) = Log File Size (MB) × 1024 ÷ Total Event Count

Bytes Per Second = Average EPS × Average Event Size (bytes)

GB/Day   = Bytes Per Second × 86,400   ÷ 1,073,741,824
GB/Week  = Bytes Per Second × 604,800  ÷ 1,073,741,824
GB/Month = Bytes Per Second × 2,592,000 ÷ 1,073,741,824   (30 days)
GB/Year  = Bytes Per Second × 31,536,000 ÷ 1,073,741,824  (365 days)
```

**Important notes:**

- These are **estimates** based on current average event sizes and rates
- Actual volumes will vary with audit policy changes, user activity, and security events
- The **Peak Estimate (3×)** should be used for infrastructure sizing to account for spikes during logon storms, incidents, or batch processing
- ForwardedEvents logs can significantly increase total volume if event forwarding is configured
- Sysmon logs tend to have higher EPS and larger event sizes than standard Windows logs

---

## WinCollect Profile Mapping

| Profile | EPS Range | Typical Use Case | Tier |
|---|---|---|---|
| **Default Endpoint** | 0–50 | Workstations, low-activity servers | 1 |
| **Typical Server** | 51–250 | File servers, print servers, standard infrastructure | 2 |
| **High Event Rate Server** | 251–625 | Domain controllers, Exchange, SQL, web servers | 3 |
| **High Event Rate (Warning)** | 625+ | Exceeds standard profiles — consider a dedicated collector | 4 |

> **Tip:** If multiple hosts fall into Tier 4, consider deploying a dedicated WinCollect standalone gateway to handle the event volume.

---

## Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|---|---|---|
| **Access Denied** | Insufficient privileges | Run PowerShell as Administrator; use domain admin credentials for remote scans |
| **Host Unreachable** | Network / firewall | Verify ICMP ping and TCP 5985/5986; check DNS resolution |
| **WinRM Not Available** | Service not configured | Run `Enable-PSRemoting -Force` on target; check TrustedHosts |
| **0 Events in Log** | Log empty or recently cleared | Marked as `Empty` status — informational, not an error |
| **ActiveDirectory Module Missing** | RSAT not installed | Server: `Add-WindowsFeature RSAT-AD-PowerShell` / Win10+: Settings → Apps → Optional Features |
| **Execution Policy Error** | Script blocked | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| **Type Conversion Error** | Single-host ArrayList unwrap | Fixed in v2.0 — ensure you're running the latest version |
| **Slow Scans on Legacy OS** | Server 2003 / XP WMI fallback | Expected behavior — WMI is significantly slower than WinEvent |

### Reading the Log File

The execution log (`EPS-Collection-Log-*.txt`) contains timestamped entries for every operation:

```
[2026-02-10 10:45:12] [Info]  Validating prerequisites...
[2026-02-10 10:45:12] [Info]  Prerequisites validated successfully.
[2026-02-10 10:45:13] [Info] VM-DC-01 Processing (1/3)...
[2026-02-10 10:45:13] [Info] VM-DC-01   Scanning Application log...
[2026-02-10 10:45:15] [Warn] VM-WKS-02 Host unreachable via ICMP ping.
[2026-02-10 10:45:20] [Error] VM-SQL-01 Failed to scan Security log: Access is denied
```

Search for `[Error]` entries to identify failures. Each entry includes the computer name and specific reason.

### Verifying WinRM Connectivity

```powershell
# Test WinRM from the scanning machine
Test-WSMan -ComputerName "target-server"

# Test with credentials
$cred = Get-Credential
Invoke-Command -ComputerName "target-server" -Credential $cred -ScriptBlock { hostname }
```

---

## Changelog

### v2.0.0

**New Features**
- Full CLI parameter support with interactive fallback
- Data volume projections: GB/Day, GB/Week, GB/Month, GB/Year per log and total
- Average event size calculation per log
- ForwardedEvents and Sysmon log support via switches
- Dual CSV output: detailed report + summary
- Persistent timestamped log file
- WinRM connectivity validation
- Structured profile suggestion objects with tier classification

**Improvements**
- Graceful per-host failure (continues scanning on errors)
- PowerShell comment-based help (`Get-Help` compatible)
- Organized code structure with regions
- Consistent parameter splatting for remote vs local
- Fixed single-host ArrayList type conversion error

### v1.0.0

- Original release by Jamie Wheaton and William Delong
- Three scan modes: Local Host, IP List, Domain
- Application, Security, System log scanning
- Basic EPS calculation and WinCollect profile suggestion
- Single CSV export with GUI dialogs

---

## Security Considerations

- **Credentials** — The script prompts for credentials for remote access. Never embed credentials in scripts or commit them to source control. Use `Get-Credential` or a secrets manager.
- **WinRM Encryption** — Use HTTPS (port 5986) with SSL certificates in production. Default HTTP (5985) transmits credentials encrypted via Kerberos/NTLM but the payload is not encrypted.
- **TrustedHosts** — Avoid wildcard (`*`) configurations. Specify exact hostnames or IP ranges.
- **Output Security** — Generated reports contain infrastructure details (hostnames, OS versions, event volumes). Handle according to your data classification policy.
- **Scan Authorization** — For domain scans, the script queries all enabled Windows computers. Ensure you have authorization before scanning.
- **Least Privilege** — Use an account with only the permissions needed: Event Log Readers group membership + WinRM access on targets.

---

## License

This project is provided as-is for internal use. See [LICENSE](LICENSE) for details.
