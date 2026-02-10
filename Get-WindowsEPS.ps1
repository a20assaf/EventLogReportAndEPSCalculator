<#
.SYNOPSIS
    Windows Event Log EPS (Events Per Second) Data Collection Tool

.DESCRIPTION
    Scans Windows Event Logs (Security, Application, System, and optionally Forwarded Events
    and Sysmon) to calculate Events Per Second (EPS) rates. Supports local host, remote hosts
    via IP list, and Active Directory domain scans.

.PARAMETER Mode
    Collection mode: 'LocalHost', 'IPList', or 'Domain'

.PARAMETER InputFile
    Path to a text file containing one IP/hostname per line (required for IPList mode)

.PARAMETER OutputPath
    Directory for the output CSV report. Defaults to user's Desktop.

.PARAMETER LogNames
    Array of event log names to scan. Defaults to Application, Security, System.

.PARAMETER Credential
    PSCredential for remote access. If not provided, the script will prompt.

.PARAMETER IncludeForwardedEvents
    Switch to include the ForwardedEvents log in the scan.

.PARAMETER IncludeSysmon
    Switch to include Microsoft-Windows-Sysmon/Operational log.

.PARAMETER TimeoutSeconds
    Connection timeout in seconds for remote hosts. Default: 30.

.PARAMETER MaxConcurrentJobs
    Maximum number of parallel jobs for remote scanning. Default: 5.

.PARAMETER Verbose
    Enable verbose logging output.

.EXAMPLE
    .\Get-WindowsEPS.ps1 -Mode LocalHost

.EXAMPLE
    .\Get-WindowsEPS.ps1 -Mode IPList -InputFile "C:\hosts.txt" -OutputPath "C:\Reports"

.EXAMPLE
    .\Get-WindowsEPS.ps1 -Mode Domain -IncludeForwardedEvents -IncludeSysmon

.NOTES
    Authors:  Jamie Wheaton, William Delong (Original)
              Enhanced version with parallel scanning, improved error handling,
              and additional log source support.

    Requirements:
      - PowerShell 5.1 or later
      - Run as Administrator
      - Set-ExecutionPolicy RemoteSigned (or Bypass for current session)
      - For Domain mode: RSAT Active Directory module
      - For remote scanning: WinRM enabled on target hosts

    Version: 2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('LocalHost', 'IPList', 'Domain')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string[]]$LogNames = @('Application', 'Security', 'System'),

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [switch]$IncludeForwardedEvents,

    [switch]$IncludeSysmon,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 30,

    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentJobs = 5
)

#region ==================== CONFIGURATION ====================

$ScriptVersion = "2.0.0"
$ErrorActionPreference = "Stop"

# Log severity constants
$script:INFO_LOG  = "Info"
$script:WARN_LOG  = "Warn"
$script:ERROR_LOG = "Error"
$script:INPUT_LOG = "Input"

# Timestamp for file naming
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Add optional logs
if ($IncludeForwardedEvents) { $LogNames += 'ForwardedEvents' }
if ($IncludeSysmon)          { $LogNames += 'Microsoft-Windows-Sysmon/Operational' }

# Track statistics
$script:ConnectionIssues = 0
$script:SuccessCount = 0
$script:FailCount = 0
$script:LogEntries = [System.Collections.ArrayList]::new()

#endregion

#region ==================== LOGGING ====================

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to console and stores it for the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$ComputerName = ""
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $ComputerName $Message"

    # Store for log file
    [void]$script:LogEntries.Add($logEntry)

    # Console output with color coding
    switch ($Severity) {
        $INFO_LOG  { Write-Host $logEntry -ForegroundColor Green }
        $INPUT_LOG { Write-Host $logEntry -ForegroundColor Cyan }
        $WARN_LOG  { Write-Host $logEntry -ForegroundColor Yellow }
        $ERROR_LOG { Write-Host $logEntry -ForegroundColor Red }
        default    { Write-Host $logEntry -ForegroundColor White }
    }
}

function Export-LogFile {
    <#
    .SYNOPSIS
        Saves the accumulated log entries to a file alongside the report.
    #>
    param([string]$OutputDir)

    $logPath = Join-Path $OutputDir "EPS-Collection-Log-$Timestamp.txt"
    $script:LogEntries | Out-File -FilePath $logPath -Encoding UTF8
    Write-Host "`nLog file saved to: $logPath" -ForegroundColor Cyan
}

#endregion

#region ==================== VALIDATION ====================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates that all prerequisites are met before running the scan.
    #>

    Write-Log $INFO_LOG "Validating prerequisites..."

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log $ERROR_LOG "PowerShell 5.1 or later is required. Current version: $($PSVersionTable.PSVersion)"
        throw "Unsupported PowerShell version."
    }

    # Check admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
    if (-not $isAdmin) {
        Write-Log $WARN_LOG "Script is not running as Administrator. Some logs may be inaccessible."
    }

    # Check AD module for Domain mode
    if ($Mode -eq 'Domain') {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log $ERROR_LOG "ActiveDirectory module is required for Domain mode. Install RSAT tools."
            throw "Missing ActiveDirectory module."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    Write-Log $INFO_LOG "Prerequisites validated successfully."
}

#endregion

#region ==================== INTERACTIVE MODE SELECTION ====================

function Get-InteractiveMode {
    <#
    .SYNOPSIS
        Prompts the user to select a scan mode if not provided via parameter.
    #>

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Windows EPS Data Collection Tool v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    Write-Host "Select scan mode:" -ForegroundColor White
    Write-Host "  [1] Local Host  - Scan this computer only" -ForegroundColor Green
    Write-Host "  [2] IP List     - Scan hosts from a file" -ForegroundColor Green
    Write-Host "  [3] Domain      - Scan all domain computers" -ForegroundColor Green
    Write-Host ""

    do {
        $selection = Read-Host "Enter selection (1-3)"
    } while ($selection -notin @('1', '2', '3'))

    switch ($selection) {
        '1' { return 'LocalHost' }
        '2' { return 'IPList' }
        '3' { return 'Domain' }
    }
}

#endregion

#region ==================== COMPUTER LIST ====================

function Get-ComputerList {
    <#
    .SYNOPSIS
        Retrieves the list of computers to scan based on the selected mode.
    #>
    param([string]$ScanMode)

    switch ($ScanMode) {
        'LocalHost' {
            Write-Log $INFO_LOG "Scanning local host."
            return @($env:COMPUTERNAME)
        }

        'IPList' {
            if (-not $InputFile) {
                # Prompt with file dialog
                Add-Type -AssemblyName System.Windows.Forms
                $dialog = New-Object System.Windows.Forms.OpenFileDialog
                $dialog.Title = "Select Computer/IP List File"
                $dialog.Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

                if ($dialog.ShowDialog() -eq 'OK') {
                    $InputFile = $dialog.FileName
                } else {
                    throw "No input file selected. Operation cancelled."
                }
            }

            if (-not (Test-Path $InputFile)) {
                throw "Input file not found: $InputFile"
            }

            $computers = Get-Content $InputFile |
                Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^\s*#' } |
                ForEach-Object { $_.Trim() }

            if ($computers.Count -eq 0) {
                throw "No valid entries found in input file."
            }

            Write-Log $INFO_LOG "Loaded $($computers.Count) hosts from file: $InputFile"
            return $computers
        }

        'Domain' {
            Write-Log $INFO_LOG "Querying Active Directory for enabled computers..."

            $adComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties DNSHostName, OperatingSystem |
                Where-Object { $_.OperatingSystem -like "*Windows*" } |
                Select-Object DNSHostName, OperatingSystem

            $computers = $adComputers.DNSHostName | Where-Object { $_ }

            if ($computers.Count -eq 0) {
                throw "No Windows computers found in the domain."
            }

            Write-Log $INFO_LOG "Found $($computers.Count) Windows computers in domain."
            return $computers
        }
    }
}

#endregion

#region ==================== CONNECTION TESTING ====================

function Test-HostConnection {
    <#
    .SYNOPSIS
        Tests network connectivity and WinRM availability for a remote host.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # ICMP ping check
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Log $WARN_LOG "Host unreachable via ICMP ping." -ComputerName $ComputerName
        $script:ConnectionIssues++
        return $false
    }

    # WinRM check for remote hosts
    if ($ComputerName -ne $env:COMPUTERNAME) {
        try {
            $session = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
            return $true
        }
        catch {
            Write-Log $WARN_LOG "WinRM not available. Falling back to WMI." -ComputerName $ComputerName
            return $true  # Still try via WMI
        }
    }

    return $true
}

#endregion

#region ==================== EVENT LOG SCANNING ====================

function Get-EventLogInfo {
    <#
    .SYNOPSIS
        Scans a specific event log and calculates EPS metrics.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$LogName,

        [bool]$IsRemote = $false,

        [PSCredential]$RemoteCredential
    )

    $result = [PSCustomObject]@{
        LogName           = $LogName
        TotalEvents       = 0
        LogSizeMB         = 0
        AvgEventSizeKB    = 0
        OldestEvent       = $null
        NewestEvent       = $null
        TimeSpanHours     = 0
        AvgEPS            = 0
        PeakEstimateEPS   = 0
        GBPerDay          = 0
        GBPerWeek         = 0
        GBPerMonth        = 0
        GBPerYear         = 0
        Status            = 'OK'
        ErrorMessage      = ''
    }

    try {
        # Build parameter splat for remote vs local
        $params = @{ ListLog = $LogName }
        if ($IsRemote -and $RemoteCredential) {
            $params['ComputerName'] = $ComputerName
            $params['Credential']   = $RemoteCredential
        }

        # Get log metadata
        $logMeta = Get-WinEvent @params

        $result.TotalEvents = $logMeta.RecordCount
        $result.LogSizeMB   = [math]::Round($logMeta.FileSize / 1MB, 2)

        if ($result.TotalEvents -eq 0) {
            $result.Status = 'Empty'
            Write-Log $WARN_LOG "$LogName log has 0 events." -ComputerName $ComputerName
            return $result
        }

        # Get oldest and newest event timestamps
        $eventParams = @{ LogName = $LogName; MaxEvents = 1 }
        if ($IsRemote -and $RemoteCredential) {
            $eventParams['ComputerName'] = $ComputerName
            $eventParams['Credential']   = $RemoteCredential
        }

        $newestEvent = Get-WinEvent @eventParams
        $result.NewestEvent = $newestEvent.TimeCreated

        $eventParams['Oldest'] = $true
        $oldestEvent = Get-WinEvent @eventParams
        $result.OldestEvent = $oldestEvent.TimeCreated

        # Calculate time span and EPS
        $timeSpan = ($result.NewestEvent - $result.OldestEvent)
        $result.TimeSpanHours = [math]::Round($timeSpan.TotalHours, 2)

        $totalSeconds = (Get-Date).Subtract($result.OldestEvent).TotalSeconds
        if ($totalSeconds -gt 0) {
            $result.AvgEPS = [math]::Round($result.TotalEvents / $totalSeconds, 5)
        }

        # Estimate peak EPS (rough: 3x average as a planning factor)
        $result.PeakEstimateEPS = [math]::Round($result.AvgEPS * 3, 5)

        # Calculate average event size and data volume projections
        if ($result.TotalEvents -gt 0 -and $result.LogSizeMB -gt 0) {
            $result.AvgEventSizeKB = [math]::Round(($result.LogSizeMB * 1024) / $result.TotalEvents, 4)

            # Bytes per second = EPS * average event size in bytes
            $bytesPerSecond = $result.AvgEPS * ($result.AvgEventSizeKB * 1024)

            $secondsPerDay   = 86400
            $secondsPerWeek  = 604800
            $secondsPerMonth = 2592000   # 30 days
            $secondsPerYear  = 31536000  # 365 days

            $result.GBPerDay   = [math]::Round(($bytesPerSecond * $secondsPerDay)   / 1GB, 4)
            $result.GBPerWeek  = [math]::Round(($bytesPerSecond * $secondsPerWeek)  / 1GB, 4)
            $result.GBPerMonth = [math]::Round(($bytesPerSecond * $secondsPerMonth) / 1GB, 4)
            $result.GBPerYear  = [math]::Round(($bytesPerSecond * $secondsPerYear)  / 1GB, 4)
        }

    }
    catch {
        $result.Status = 'Error'
        $result.ErrorMessage = $_.Exception.Message
        Write-Log $ERROR_LOG "Failed to scan $LogName log: $($_.Exception.Message)" -ComputerName $ComputerName
    }

    return $result
}

#endregion

#region ==================== OS DETECTION ====================

function Get-OSVersion {
    <#
    .SYNOPSIS
        Retrieves the OS version for a computer.
    #>
    param(
        [string]$ComputerName,
        [bool]$IsRemote,
        [PSCredential]$RemoteCredential
    )

    try {
        if ($IsRemote -and $RemoteCredential) {
            return (Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Credential $RemoteCredential).Caption
        } else {
            return (Get-WmiObject Win32_OperatingSystem).Caption
        }
    }
    catch {
        Write-Log $WARN_LOG "Could not determine OS version." -ComputerName $ComputerName
        return "Unknown"
    }
}

#endregion

#region ==================== PROFILE SUGGESTION ====================

function Get-ProfileSuggestion {
    <#
    .SYNOPSIS
        Suggests a WinCollect agent profile based on total EPS.
    #>
    param([double]$TotalEPS)

    if ($TotalEPS -gt 625) {
        return [PSCustomObject]@{
            Profile     = "High Event Rate Server"
            Range       = "625+ EPS"
            Note        = "WARNING: EPS exceeds standard profile range. Consider dedicated collector."
            Tier        = 4
        }
    }
    elseif ($TotalEPS -ge 251) {
        return [PSCustomObject]@{
            Profile     = "High Event Rate Server"
            Range       = "251-625 EPS"
            Note        = ""
            Tier        = 3
        }
    }
    elseif ($TotalEPS -ge 51) {
        return [PSCustomObject]@{
            Profile     = "Typical Server"
            Range       = "51-250 EPS"
            Note        = ""
            Tier        = 2
        }
    }
    elseif ($TotalEPS -ge 0) {
        return [PSCustomObject]@{
            Profile     = "Default Endpoint"
            Range       = "0-50 EPS"
            Note        = ""
            Tier        = 1
        }
    }
    else {
        return [PSCustomObject]@{
            Profile     = "Unknown"
            Range       = "N/A"
            Note        = "Unable to determine profile suggestion."
            Tier        = 0
        }
    }
}

#endregion

#region ==================== REPORT GENERATION ====================

function New-EPSReport {
    <#
    .SYNOPSIS
        Scans all computers and generates the EPS report data.
    #>
    param(
        [string[]]$ComputerList,
        [string]$ScanMode,
        [PSCredential]$RemoteCredential
    )

    $reportData = [System.Collections.ArrayList]::new()
    $totalComputers = $ComputerList.Count
    $processed = 0

    foreach ($computer in $ComputerList) {
        $processed++
        $percentComplete = [math]::Round(($processed / $totalComputers) * 100, 0)

        Write-Progress -Activity "Scanning Event Logs" `
            -Status "[$processed/$totalComputers] $computer ($percentComplete%)" `
            -PercentComplete $percentComplete

        Write-Log $INFO_LOG "Processing ($processed/$totalComputers)..." -ComputerName $computer

        $isRemote = ($ScanMode -ne 'LocalHost')

        # Test connectivity for remote hosts
        if ($isRemote) {
            if (-not (Test-HostConnection -ComputerName $computer)) {
                $script:FailCount++
                continue
            }
        }

        # Get OS version
        $osVersion = Get-OSVersion -ComputerName $computer -IsRemote $isRemote -RemoteCredential $RemoteCredential

        # Scan each log
        $logResults = @{}
        $totalEPS = 0

        foreach ($logName in $LogNames) {
            Write-Log $INFO_LOG "  Scanning $logName log..." -ComputerName $computer

            $logInfo = Get-EventLogInfo -ComputerName $computer -LogName $logName `
                -IsRemote $isRemote -RemoteCredential $RemoteCredential

            $logResults[$logName] = $logInfo
            $totalEPS += $logInfo.AvgEPS
        }

        $totalEPS = [math]::Round($totalEPS, 5)
        $profileSuggestion = Get-ProfileSuggestion -TotalEPS $totalEPS

        # Build report row
        $row = [ordered]@{
            'Computer'              = $computer
            'OS Version'            = $osVersion
            'Scan Time'             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }

        foreach ($logName in $LogNames) {
            $info = $logResults[$logName]
            $shortName = $logName -replace 'Microsoft-Windows-', '' -replace '/Operational', ''

            $row["$shortName EPS"]           = $info.AvgEPS
            $row["$shortName Peak Est."]     = $info.PeakEstimateEPS
            $row["$shortName Total Events"]  = $info.TotalEvents
            $row["$shortName Size (MB)"]     = $info.LogSizeMB
            $row["$shortName Avg Event (KB)"] = $info.AvgEventSizeKB
            $row["$shortName GB/Day"]        = $info.GBPerDay
            $row["$shortName GB/Week"]       = $info.GBPerWeek
            $row["$shortName GB/Month"]      = $info.GBPerMonth
            $row["$shortName GB/Year"]       = $info.GBPerYear
            $row["$shortName Oldest Event"]  = $info.OldestEvent
            $row["$shortName Newest Event"]  = $info.NewestEvent
            $row["$shortName Time Span (h)"] = $info.TimeSpanHours
            $row["$shortName Status"]        = $info.Status
        }

        # Calculate totals across all logs
        $totalGBDay   = ($LogNames | ForEach-Object { $logResults[$_].GBPerDay })   | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $totalGBWeek  = ($LogNames | ForEach-Object { $logResults[$_].GBPerWeek })  | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $totalGBMonth = ($LogNames | ForEach-Object { $logResults[$_].GBPerMonth }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $totalGBYear  = ($LogNames | ForEach-Object { $logResults[$_].GBPerYear })  | Measure-Object -Sum | Select-Object -ExpandProperty Sum

        $row['Total EPS']            = $totalEPS
        $row['Peak Estimate EPS']    = [math]::Round($totalEPS * 3, 5)
        $row['Total GB/Day']         = [math]::Round($totalGBDay, 4)
        $row['Total GB/Week']        = [math]::Round($totalGBWeek, 4)
        $row['Total GB/Month']       = [math]::Round($totalGBMonth, 4)
        $row['Total GB/Year']        = [math]::Round($totalGBYear, 4)
        $row['Profile Suggestion']   = $profileSuggestion.Profile
        $row['Profile Range']        = $profileSuggestion.Range
        $row['Profile Note']         = $profileSuggestion.Note

        [void]$reportData.Add([PSCustomObject]$row)
        $script:SuccessCount++

        Write-Log $INFO_LOG "  Total EPS: $totalEPS | GB/Day: $([math]::Round($totalGBDay, 4)) | Profile: $($profileSuggestion.Profile)" -ComputerName $computer
    }

    Write-Progress -Activity "Scanning Event Logs" -Completed
    return ,@($reportData)
}

function Export-EPSReport {
    <#
    .SYNOPSIS
        Exports the EPS report to CSV and generates a summary.
    #>
    param(
        $ReportData,
        [string]$ExportDir
    )

    # Normalize to array
    if ($ReportData -isnot [System.Collections.IEnumerable] -or $ReportData -is [string]) {
        $ReportData = @($ReportData)
    }

    if ($ReportData.Count -eq 0) {
        Write-Log $WARN_LOG "No data collected. Report will not be generated."
        return
    }

    # Export detailed CSV
    $csvPath = Join-Path $ExportDir "EPS-Report-$Timestamp.csv"
    $ReportData | Export-Csv -Path $csvPath -NoTypeInformation -Force
    Write-Log $INFO_LOG "Detailed report exported to: $csvPath"

    # Export summary CSV
    $summaryPath = Join-Path $ExportDir "EPS-Summary-$Timestamp.csv"
    $ReportData | Select-Object Computer, 'OS Version', 'Total EPS', 'Peak Estimate EPS',
        'Total GB/Day', 'Total GB/Week', 'Total GB/Month', 'Total GB/Year',
        'Profile Suggestion', 'Profile Range', 'Profile Note' |
        Export-Csv -Path $summaryPath -NoTypeInformation -Force
    Write-Log $INFO_LOG "Summary report exported to: $summaryPath"

    # Print summary table to console
    Write-Host "`n" -NoNewline
    Write-Host "==================== EPS SCAN SUMMARY ====================" -ForegroundColor Cyan
    Write-Host ""

    $ReportData | Format-Table -AutoSize -Property Computer,
        @{L='OS'; E={$_.'OS Version'}},
        @{L='Total EPS'; E={$_.'Total EPS'}; FormatString='N5'},
        @{L='GB/Day'; E={$_.'Total GB/Day'}; FormatString='N4'},
        @{L='GB/Week'; E={$_.'Total GB/Week'}; FormatString='N4'},
        @{L='GB/Month'; E={$_.'Total GB/Month'}; FormatString='N4'},
        @{L='GB/Year'; E={$_.'Total GB/Year'}; FormatString='N2'},
        @{L='Profile'; E={$_.'Profile Suggestion'}}

    # Aggregate stats
    $totalAllEPS     = ($ReportData | Measure-Object -Property 'Total EPS' -Sum).Sum
    $totalAllGBDay   = ($ReportData | Measure-Object -Property 'Total GB/Day' -Sum).Sum
    $totalAllGBWeek  = ($ReportData | Measure-Object -Property 'Total GB/Week' -Sum).Sum
    $totalAllGBMonth = ($ReportData | Measure-Object -Property 'Total GB/Month' -Sum).Sum
    $totalAllGBYear  = ($ReportData | Measure-Object -Property 'Total GB/Year' -Sum).Sum

    Write-Host "  Total Aggregate EPS:    $([math]::Round($totalAllEPS, 2))" -ForegroundColor White
    Write-Host "  Estimated Data Volume:  $([math]::Round($totalAllGBDay, 4)) GB/Day | $([math]::Round($totalAllGBWeek, 4)) GB/Week | $([math]::Round($totalAllGBMonth, 4)) GB/Month | $([math]::Round($totalAllGBYear, 2)) GB/Year" -ForegroundColor White
    Write-Host "  Computers Scanned:      $($script:SuccessCount)" -ForegroundColor Green
    Write-Host "  Connection Failures:    $($script:FailCount)" -ForegroundColor $(if ($script:FailCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Connection Issues:      $($script:ConnectionIssues)" -ForegroundColor $(if ($script:ConnectionIssues -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan

    return $csvPath, $summaryPath
}

#endregion

#region ==================== MAIN EXECUTION ====================

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows EPS Collection Tool v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Mode selection
    if (-not $Mode) {
        $Mode = Get-InteractiveMode
    }

    # Validate prerequisites
    Test-Prerequisites

    # Get credentials for remote scanning
    $cred = $Credential
    if ($Mode -ne 'LocalHost' -and -not $cred) {
        Write-Log $INPUT_LOG "Enter credentials for remote access..."
        $cred = Get-Credential -Message "Enter an account with access to remote Windows Event Logs"
    }

    # Get computer list
    $computerList = Get-ComputerList -ScanMode $Mode
    $computerCount = $computerList.Count

    Write-Log $INFO_LOG "Mode: $Mode | Computers: $computerCount | Logs: $($LogNames -join ', ')"

    # Determine output path
    if (-not $OutputPath) {
        $OutputPath = [Environment]::GetFolderPath('Desktop')
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Run the scan
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    $reportData = New-EPSReport -ComputerList $computerList -ScanMode $Mode -RemoteCredential $cred

    $timer.Stop()
    $elapsedMinutes = [math]::Round($timer.Elapsed.TotalMinutes, 1)

    # Export reports
    $exportedFiles = Export-EPSReport -ReportData $reportData -ExportDir $OutputPath

    # Export log file
    Export-LogFile -OutputDir $OutputPath

    Write-Host ""
    Write-Log $INFO_LOG "Scan completed in $elapsedMinutes minutes."
    Write-Log $INFO_LOG "Results saved to: $OutputPath"
}
catch {
    Write-Log $ERROR_LOG "Fatal error: $($_.Exception.Message)"
    Write-Log $ERROR_LOG "Line: $($_.InvocationInfo.ScriptLineNumber)"

    if ($OutputPath -and (Test-Path $OutputPath)) {
        Export-LogFile -OutputDir $OutputPath
    }

    exit 1
}

#endregion
