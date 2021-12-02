# ParseFirewallLog

### CMDLet: Get-WindowsFirewallLog

#### Reads the Firewall.log from ($env:windir\system32\LogFiles\Firewall\pfirewall.log) or given logfile and outputs a PSCustomObject

```
# Samples

Sample1:
Get-WindowsFirewallLog  Select-Object -Property Date, Time, Action, Protocol, Source, SrcPort, Destination, DstPort, Size, Direction | Where-Object { $_.Protocol -eq "UDP" -and $_.Action -eq "DROP" } | Format-Table -AutoSize

Other samples:
$prop = @("Date", "Action", "Protocol", "Source", "SrcPort", "Destination", "DstPort", "Direction")

Get-WindowsFirewallLog .\pfirewall.log | Select-Object -Property $prop | Where-Object { $_.Protocol -eq 'UDP' -or $_.Protocol -eq 'TCP' } | Group-Object -Property Action, Direction | Select-Object -ExpandProperty Group| Get-Unique -AsString |Format-Table -AutoSize

Get-WindowsFirewallLog -LogFile .\pfirewall.log | Select-Object -Property $prop | Group-Object -Property Action, Direction | Where-Object { $_.Name -eq 'DROP, RECEIVE' -or $_.Name -eq 'ALLOW, SEND' } |  Format-Table -AutoSize

Get-WindowsFirewallLog -LogFile .\pfirewall.log | Select-Object -Property $prop | Group-Object -Property Action, Direction | Format-Table -AutoSize

Get-WindowsFirewallLog -LogFile .\pfirewall.log | Select-Object -Property $prop | Group-Object -Property $prop | Format-Table -AutoSize

```

## Output

Date      | Time  | Action |Protocol |Source      |SrcPort|Destination |DstPort|Size|Direction
:---------|-------|:-------|:--------|:-----------|:-----|:------------|:------|:---|:---------
2021-06-22| 12:19:41 | DROP | UDP    |   192.168.178.25 | 5353  |   224.0.0.251    |  5353  |   73  |  RECEIVE
2021-06-22| 12:19:41 | DROP | UDP    |   192.168.178.42 | 5353  |   224.0.0.251    |  5353  |   225 |  RECEIVE
2021-06-22| 12:20:29 | DROP | UDP    |   192.168.178.31 | 5353  |   224.0.0.251    |  5353  |   77  |  RECEIVE
2021-06-22| 12:20:29 | ALLOW| UDP    |   192.168.178.51 | 60946 |   192.168.178.1  |  53    |   0   |  SEND
2021-06-22| 12:20:29 | ALLOW| UDP    |   192.168.178.51 | 59998 |   192.168.178.1  |  53    |   0   |  SEND
2021-06-22| 12:20:30 | ALLOW| TCP    |   192.168.178.51 | 49152 |   52.114.104.174 |  443   |   0   |  SEND
