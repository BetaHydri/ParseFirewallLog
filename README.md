# ParseFirewallLog

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://github.com/BetaHydri/ParseFirewallLog)

A PowerShell function that parses **Windows Firewall log files** into structured objects, making it easy to filter, group, and analyze firewall activity.

## Features

- Parses the default Windows Firewall log (`pfirewall.log`) or any specified log file
- Outputs `PSCustomObject` with typed properties (Date, Time, Action, Protocol, Source, Destination, Ports, etc.)
- Supports IPv4 log entries
- Works seamlessly with PowerShell's pipeline for filtering, grouping, and formatting

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Windows Firewall logging enabled (see [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging))

## Installation

Download or clone this repository and dot-source the script:

```powershell
. .\ParseFirewallLog.ps1
```

## Usage

### Basic — read the default firewall log

```powershell
Get-WindowsFirewallLog | Format-Table -AutoSize
```

### Filter dropped UDP packets

```powershell
Get-WindowsFirewallLog |
    Select-Object Date, Time, Action, Protocol, Source, SrcPort, Destination, DstPort, Size, Direction |
    Where-Object { $_.Protocol -eq 'UDP' -and $_.Action -eq 'DROP' } |
    Format-Table -AutoSize
```

### Parse a specific log file and group by action/direction

```powershell
$prop = @('Date', 'Action', 'Protocol', 'Source', 'SrcPort', 'Destination', 'DstPort', 'Direction')

Get-WindowsFirewallLog -LogFile .\pfirewall.log |
    Select-Object -Property $prop |
    Group-Object -Property Action, Direction |
    Format-Table -AutoSize
```

### Filter for specific traffic patterns

```powershell
Get-WindowsFirewallLog -LogFile .\pfirewall.log |
    Select-Object -Property $prop |
    Group-Object -Property Action, Direction |
    Where-Object { $_.Name -eq 'DROP, RECEIVE' -or $_.Name -eq 'ALLOW, SEND' } |
    Format-Table -AutoSize
```

### Deduplicate unique connections

```powershell
Get-WindowsFirewallLog -LogFile .\pfirewall.log |
    Select-Object -Property $prop |
    Where-Object { $_.Protocol -eq 'UDP' -or $_.Protocol -eq 'TCP' } |
    Group-Object -Property Action, Direction |
    Select-Object -ExpandProperty Group |
    Get-Unique -AsString |
    Format-Table -AutoSize
```

## Sample Output

| Date       | Time     | Action | Protocol | Source          | SrcPort | Destination     | DstPort | Size | Direction |
|:-----------|:---------|:-------|:---------|:----------------|:--------|:----------------|:--------|:-----|:----------|
| 2021-06-22 | 12:19:41 | DROP   | UDP      | 192.168.178.25  | 5353    | 224.0.0.251     | 5353    | 73   | RECEIVE   |
| 2021-06-22 | 12:19:41 | DROP   | UDP      | 192.168.178.42  | 5353    | 224.0.0.251     | 5353    | 225  | RECEIVE   |
| 2021-06-22 | 12:20:29 | DROP   | UDP      | 192.168.178.31  | 5353    | 224.0.0.251     | 5353    | 77   | RECEIVE   |
| 2021-06-22 | 12:20:29 | ALLOW  | UDP      | 192.168.178.51  | 60946   | 192.168.178.1   | 53     | 0    | SEND      |
| 2021-06-22 | 12:20:29 | ALLOW  | UDP      | 192.168.178.51  | 59998   | 192.168.178.1   | 53     | 0    | SEND      |
| 2021-06-22 | 12:20:30 | ALLOW  | TCP      | 192.168.178.51  | 49152   | 52.114.104.174  | 443    | 0    | SEND      |

## Parameters

| Parameter  | Type       | Default                                                        | Description                        |
|:-----------|:-----------|:---------------------------------------------------------------|:-----------------------------------|
| `-LogFile` | `String[]` | `$env:windir\system32\LogFiles\Firewall\pfirewall.log` | Path to one or more firewall log files |

## License

This project is licensed under the [MIT License](LICENSE).
