
<#PSScriptInfo

.VERSION 1.0.0

.GUID 3bc11438-f787-4e45-a3f9-bc322d1e8d0f

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2021

.TAGS Firewall, Log, 'Windows Firewall', Parser

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION 
 Parses the Windows Firewall logfile to be able to filter for specific attribuites 

#> 

Param()


#Firewall Log Parsing with RegEx
Function Get-WindowsFirewallLog {

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [String[]]
        $LogFile = @("$env:windir\system32\LogFiles\Firewall\pfirewall.log")
    )
    # IPv4 RegEx for Windows Firewall Log.
    [regex]$regex = '(?<Date>\d{4}-\d{2}-\d{2})\s(?<Time>\d{1,2}:\d{1,2}:\d{1,2})\s(?<Action>\w{4,5})\s(?<Protocol>\w{3})\s(?<Source>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?<Destination>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?<SrcPort>\d+)\s(?<DstPort>\d+)\s(?<Size>\d+)\s(?<tcpflags>-|\d+)\s(?<tcpsyn>-|\d+)\s(?<tcpack>-|\d+)\s(?<tcpwin>-|\d+)\s(?<icmptype>-|\d+)\s(?<icmpcode>-|\d+)\s(?<info>-|\d+)\s(?<Direction>RECEIVE|SEND)'
    #$Matches = $null
    $myArray = @()

    foreach ($item in (Get-Content -Path $LogFile)) {
        if ($item -match $regex) {
            $Matches.Remove(0)         
            $myArray += [PSCustomObject]$Matches
        }
    }
    return $myArray
}

#Samples
#Get-WindowsFirewallLog -LogFile .\pfirewall.log | Select-Object -Property Date, Time, Action, Protocol, Source, SrcPort, Destination, DstPort, Size, Direction | Format-Table -AutoSize
