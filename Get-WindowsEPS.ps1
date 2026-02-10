# Get-WindowsEPS.ps1

PowerShell script to scan Windows Event Logs and calculate EPS (Events Per Second) rates with storage volume projections. Built for SIEM sizing, WinCollect profile selection, and capacity planning.

Supports scanning localhost, a list of remote hosts, or all computers in an AD domain.

## Table of Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Parameters](#parameters)
- [Output](#output)
- [How data volume is calculated](#how-data-volume-is-calculated)
- [WinCollect profiles](#wincollect-profiles)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Security notes](#security-notes)

## What it does

The script reads the Application, Security, and System event logs (plus ForwardedEvents and Sysmon if you enable them) and calculates:

- Average EPS per log and combined total
- Peak EPS estimate (3x the average, for sizing purposes)
- Average event size per log
- Projected data volume in GB/Day, GB/Week, GB/Month, GB/Year
- A WinCollect agent profile recommendation based on total EPS

Everything gets exported to CSV files you can hand off to whoever is doing the SIEM sizing.

## Requirements

| What | Why |
|---|---|
| PowerShell 5.1+ | `$PSVersionTable.PSVersion` to check |
| Run as admin | Needed to read the Security log |
| Execution policy set to RemoteSigned | `Get-ExecutionPolicy` to check |
| RSAT AD module | Only if you're doing a domain-wide scan |
| WinRM enabled on targets | Only for remote scanning (TCP 5985/5986) |
| Network access / ICMP | Ping + WinRM ports open to target hosts |

## Setup

Grab the script and drop it somewhere:

```powershell
git clone https://github.com/your-org/windows-eps-tool.git
cd windows-eps-tool
```

Or just download the `.ps1` directly.

Set execution policy if you haven't:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

If you're scanning remote boxes, make sure WinRM is enabled on them:

```powershell
# run on each target (or push via GPO)
Enable-PSRemoting -Force

# on your scanning machine, trust the targets
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.*" -Force
```

## Usage

### Quick start

Just run it with no parameters and it'll walk you through it:

```powershell
.\Get-WindowsEPS.ps1
```

You get a menu:

```
========================================
  Windows EPS Data Collection Tool v2.0.0
========================================

Select scan mode:
  [1] Local Host  - Scan this computer only
  [2] IP List     - Scan hosts from a file
  [3] Domain      - Scan all domain computers
```

### Scan this machine

```powershell
.\Get-WindowsEPS.ps1 -Mode LocalHost
```

No credentials needed. Just runs against local logs.

### Scan a list of hosts

```powershell
.\Get-WindowsEPS.ps1 -Mode IPList -InputFile "C:\hosts.txt"
```

The file is just one hostname or IP per line. Lines starting with `#` are comments.

```text
# DCs
dc01.corp.local
dc02.corp.local

# file servers
192.168.1.50
192.168.1.51
```

### Scan the whole domain

```powershell
.\Get-WindowsEPS.ps1 -Mode Domain
```

Pulls all enabled Windows machines from AD and scans them. You'll need the RSAT AD PowerShell module installed.

### More examples

```powershell
# include ForwardedEvents and Sysmon
.\Get-WindowsEPS.ps1 -Mode LocalHost -IncludeForwardedEvents -IncludeSysmon

# custom output folder
.\Get-WindowsEPS.ps1 -Mode IPList -InputFile "servers.txt" -OutputPath "D:\EPSReports"

# pass credentials upfront (good for scripted runs)
$cred = Get-Credential
.\Get-WindowsEPS.ps1 -Mode Domain -Credential $cred -OutputPath "C:\Reports"

# only scan Security + Sysmon
.\Get-WindowsEPS.ps1 -Mode LocalHost -LogNames @('Security') -IncludeSysmon
```

## Parameters

| Parameter | Type | Default | What it does |
|---|---|---|---|
| `-Mode` | String | interactive prompt | `LocalHost`, `IPList`, or `Domain` |
| `-InputFile` | String | file picker dialog | Text file with one host per line (IPList mode) |
| `-OutputPath` | String | Desktop | Where to save the reports |
| `-LogNames` | String[] | Application, Security, System | Which event logs to scan |
| `-Credential` | PSCredential | prompts you | Creds for remote access |
| `-IncludeForwardedEvents` | Switch | off | Add ForwardedEvents to the scan |
| `-IncludeSysmon` | Switch | off | Add Sysmon operational log to the scan |
| `-TimeoutSeconds` | Int | 30 | How long to wait for remote connections |
| `-MaxConcurrentJobs` | Int | 5 | Parallel scan limit |

## Output

You get three files in your output directory:

| File | What's in it |
|---|---|
| `EPS-Report-<timestamp>.csv` | Full breakdown per log per machine |
| `EPS-Summary-<timestamp>.csv` | One row per machine with totals |
| `EPS-Collection-Log-<timestamp>.txt` | Execution log with timestamps and errors |

### Detailed report columns

Per log (Application, Security, System, etc.):

| Column | What it is |
|---|---|
| `<Log> EPS` | Average events/sec |
| `<Log> Peak Est.` | 3x the average (planning buffer) |
| `<Log> Total Events` | Event count |
| `<Log> Size (MB)` | Log file size |
| `<Log> Avg Event (KB)` | Log size / event count |
| `<Log> GB/Day` | Projected daily volume |
| `<Log> GB/Week` | Projected weekly volume |
| `<Log> GB/Month` | Projected monthly volume (30d) |
| `<Log> GB/Year` | Projected yearly volume (365d) |
| `<Log> Oldest Event` | First event timestamp |
| `<Log> Newest Event` | Last event timestamp |
| `<Log> Time Span (h)` | Hours between first and last |
| `<Log> Status` | OK, Empty, or Error |

Totals across all logs:

| Column | What it is |
|---|---|
| `Total EPS` | Sum of all log EPS |
| `Peak Estimate EPS` | 3x total average |
| `Total GB/Day` | Combined daily volume |
| `Total GB/Week` | Combined weekly volume |
| `Total GB/Month` | Combined monthly volume |
| `Total GB/Year` | Combined yearly volume |
| `Profile Suggestion` | WinCollect profile recommendation |
| `Profile Range` | EPS band for that profile |
| `Profile Note` | Warning if EPS is unusually high |

### Summary report columns

| Column | What it is |
|---|---|
| `Computer` | Hostname or IP |
| `OS Version` | Windows version |
| `Total EPS` | Combined EPS |
| `Peak Estimate EPS` | 3x average |
| `Total GB/Day` through `Total GB/Year` | Volume projections |
| `Profile Suggestion` | Recommended profile |
| `Profile Range` | EPS band |
| `Profile Note` | Warnings if any |

### What the console output looks like

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

## How data volume is calculated

Pretty straightforward:

```
Avg Event Size (KB)  = Log Size (MB) * 1024 / Total Events
Bytes/sec            = EPS * Avg Event Size (bytes)

GB/Day   = Bytes/sec * 86400    / 1073741824
GB/Week  = Bytes/sec * 604800   / 1073741824
GB/Month = Bytes/sec * 2592000  / 1073741824    (assumes 30 days)
GB/Year  = Bytes/sec * 31536000 / 1073741824    (assumes 365 days)
```

Keep in mind:

- These are estimates based on what's currently in the logs. If you change audit policies or enable new Sysmon rules, the numbers will shift.
- Use the Peak Estimate (3x) column when doing actual infrastructure sizing. Logon storms, security incidents, and batch jobs can spike well above average.
- ForwardedEvents can dominate the total if you have event forwarding configured across many sources.
- Sysmon tends to generate more events with bigger payloads than the standard Windows logs, especially with verbose configs.

## WinCollect profiles

| Profile | EPS Range | Typical hosts | Tier |
|---|---|---|---|
| Default Endpoint | 0-50 | Workstations, low-traffic servers | 1 |
| Typical Server | 51-250 | File/print servers, general infra | 2 |
| High Event Rate Server | 251-625 | DCs, Exchange, SQL, busy web servers | 3 |
| High Event Rate (Warning) | 625+ | Over standard range, look at a dedicated collector | 4 |

If you've got multiple machines hitting Tier 4, you probably want a dedicated WinCollect standalone gateway rather than trying to run agents locally on each box.

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| Access Denied | Not running as admin, or creds don't have access | Run as Administrator, use domain admin for remote |
| Host unreachable | Firewall or DNS | Check that ICMP and TCP 5985/5986 are open, verify name resolution |
| WinRM not available | Service not enabled | `Enable-PSRemoting -Force` on the target |
| 0 events in a log | Log is empty or was cleared | Normal, shows as "Empty" status |
| AD module not found | RSAT not installed | `Add-WindowsFeature RSAT-AD-PowerShell` on servers, or Optional Features on Win10/11 |
| Execution policy error | Scripts blocked | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Type conversion error on single host | Bug in v1.x | Fixed in v2.0, make sure you have the latest script |
| Really slow on old servers | 2003/XP uses WMI fallback | Expected, WMI is just slow on those boxes |

### Checking the log file

The log file (`EPS-Collection-Log-*.txt`) has timestamped entries:

```
[2026-02-10 10:45:12] [Info]  Validating prerequisites...
[2026-02-10 10:45:13] [Info] VM-DC-01 Processing (1/3)...
[2026-02-10 10:45:13] [Info] VM-DC-01   Scanning Application log...
[2026-02-10 10:45:15] [Warn] VM-WKS-02 Host unreachable via ICMP ping.
[2026-02-10 10:45:20] [Error] VM-SQL-01 Failed to scan Security log: Access is denied
```

Grep for `[Error]` to find failures fast.

### Testing WinRM before you scan

```powershell
Test-WSMan -ComputerName "target-server"

# or test with actual credentials
$cred = Get-Credential
Invoke-Command -ComputerName "target-server" -Credential $cred -ScriptBlock { hostname }
```

## Changelog

### v2.0.0

New stuff:
- CLI parameters (no more GUI-only), falls back to interactive if you don't pass anything
- GB/Day, GB/Week, GB/Month, GB/Year volume projections per log and total
- Average event size calculation
- ForwardedEvents and Sysmon support (`-IncludeForwardedEvents`, `-IncludeSysmon`)
- Two CSV outputs: detailed + summary
- Log file saved alongside reports
- WinRM check before scanning remote hosts
- Profile suggestions now have tier numbers

Fixed/improved:
- Doesn't die if one host fails, keeps going through the rest
- Works with `Get-Help` now (comment-based help)
- Fixed the ArrayList type error when scanning a single host
- Cleaner code layout with regions

### v1.0.0

Original version by Jamie Wheaton and William Delong.
- Local, IP list, and domain scan modes
- Application/Security/System logs
- EPS calculation with WinCollect profile suggestion
- Single CSV export, GUI-based dialogs

## Security notes

- Don't hardcode credentials in the script or check them into git. The script prompts for them or accepts a PSCredential object.
- For production use, configure WinRM over HTTPS (port 5986) with proper certs. The default HTTP transport encrypts creds via Kerberos/NTLM but doesn't encrypt the payload.
- Don't use `TrustedHosts = *` in production. Scope it to specific hosts or subnets.
- The output CSVs contain hostnames, OS versions, and event volume data. Treat them accordingly based on your org's classification policy.
- Make sure you're authorized to scan whatever you're pointing this at, especially in domain mode where it'll hit every enabled Windows machine it finds.
- Least privilege: Event Log Readers group + WinRM access is all you need on the targets. Don't use a full domain admin if you can avoid it.
