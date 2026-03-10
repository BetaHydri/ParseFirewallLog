# How to Enable Windows Firewall Logging

Windows Firewall logging is **disabled by default**. This guide covers all available methods to enable it, along with best practices and troubleshooting tips.

---

## Methods to Enable Firewall Logging

### 1. Windows Security GUI

1. Open **Windows Security** → **Firewall & network protection**
2. Click **Advanced settings** (opens `wf.msc`)
3. Right-click **Windows Defender Firewall with Advanced Security** → **Properties**
4. Select the profile tab you want to configure (**Domain**, **Private**, or **Public**)
5. Under **Logging**, click **Customize…**
6. Set **Log dropped packets** to **Yes**
7. Set **Log successful connections** to **Yes**
8. Confirm the log file path (default: `%windir%\system32\LogFiles\Firewall\pfirewall.log`)
9. Set **Size limit** as needed (default: 4096 KB)
10. Click **OK** on all dialogs

### 2. PowerShell (`Set-NetFirewallProfile`)

```powershell
# Enable logging for all profiles (Domain, Private, Public)
Set-NetFirewallProfile -Profile Domain, Private, Public `
    -LogBlocked True `
    -LogAllowed True `
    -LogFileName "%windir%\system32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 4096
```

```powershell
# Enable logging only for the Domain profile
Set-NetFirewallProfile -Profile Domain -LogBlocked True -LogAllowed True
```

```powershell
# Verify current logging settings
Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed, LogFileName, LogMaxSizeKilobytes | Format-Table -AutoSize
```

### 3. `netsh advfirewall`

```cmd
:: Enable for all profiles
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging filename "%windir%\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging maxfilesize 4096
```

```cmd
:: Enable for a single profile
netsh advfirewall set domainprofile logging droppedconnections enable
netsh advfirewall set domainprofile logging allowedconnections enable
```

```cmd
:: Verify settings
netsh advfirewall show allprofiles logging
```

### 4. Group Policy (`gpedit.msc` / Domain GPO)

1. Open **Group Policy Editor** (`gpedit.msc` for local, or **GPMC** for domain)
2. Navigate to:
   ```
   Computer Configuration
     → Administrative Templates
       → Network
         → Network Connections
           → Windows Defender Firewall
             → Domain Profile / Standard Profile
   ```
3. Open **Windows Defender Firewall: Allow logging**
4. Configure:
   - **Log dropped packets**: Yes
   - **Log successful connections**: Yes
   - **Log file path and name**: `%windir%\system32\LogFiles\Firewall\pfirewall.log`
   - **Size limit (KB)**: 4096
5. Click **OK** and run `gpupdate /force`

> **Tip**: In a domain environment, deploy via GPO to ensure consistent logging across all machines.

### 5. Registry (for scripting/automation)

The firewall logging settings are stored under:

```
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<Profile>\Logging
```

Where `<Profile>` is `DomainProfile`, `StandardProfile`, or `PublicProfile`.

| Value Name             | Type      | Data        | Description                  |
|:-----------------------|:----------|:------------|:-----------------------------|
| `LogDroppedPackets`    | REG_DWORD | `1` (enable) | Log blocked connections     |
| `LogSuccessfulConnections` | REG_DWORD | `1` (enable) | Log allowed connections |
| `LogFilePath`          | REG_SZ    | Full path   | Path to the log file        |
| `LogFileSize`          | REG_DWORD | Size in KB  | Maximum log file size       |

```powershell
# Example: Enable dropped-packet logging for the Domain profile via registry
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force }
Set-ItemProperty -Path $regPath -Name LogDroppedPackets -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name LogSuccessfulConnections -Value 1 -Type DWord
```

> **Note**: Registry changes require a policy refresh (`gpupdate /force`) or reboot to take effect.

---

## Best Practices

| Practice | Rationale |
|:---------|:----------|
| Enable logging on **all profiles** (Domain, Private, Public) | A machine may switch profiles; ensure no blind spots |
| Log **both** dropped and allowed connections | Dropped-only misses legitimate traffic analysis; allowed-only misses attack detection |
| Increase log size to **16384 KB or higher** for busy servers | The default 4096 KB rotates quickly on high-traffic systems |
| Use a **custom log path** on a dedicated drive for servers | Prevents filling the system drive and improves I/O |
| Deploy settings via **Group Policy** in domain environments | Ensures consistency and prevents local overrides |
| Monitor log file **rotation** | Windows Firewall overwrites the oldest entries when the size limit is reached — no automatic archival |
| Collect logs centrally with a **SIEM** or scheduled task | The local log is volatile; archive it before it rotates |

---

## Troubleshooting

### Log file is not created

**Symptom**: The file `%windir%\system32\LogFiles\Firewall\pfirewall.log` does not exist even after enabling logging.

**Causes & fixes**:

1. **Folder permissions**
   The Windows Firewall service (`MpsSvc`) runs as `NT SERVICE\mpssvc`. This account needs **Write** permission on the log folder. If permissions were tightened or the folder was recreated, the service cannot write the log.

   ```powershell
   # Check current ACL
   Get-Acl "$env:windir\system32\LogFiles\Firewall" | Format-List

   # Reset permissions (run as Administrator)
   $acl = Get-Acl "$env:windir\system32\LogFiles\Firewall"
   $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
       "NT SERVICE\mpssvc", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
   )
   $acl.SetAccessRule($rule)
   Set-Acl -Path "$env:windir\system32\LogFiles\Firewall" -AclObject $acl
   ```

2. **Folder does not exist**
   If the `Firewall` subfolder was deleted, recreate it and set the correct permissions:

   ```powershell
   New-Item -Path "$env:windir\system32\LogFiles\Firewall" -ItemType Directory -Force
   # Then apply the ACL fix above
   ```

3. **Windows Firewall service is not running**
   ```powershell
   Get-Service -Name MpsSvc | Select-Object Name, Status, StartType

   # Start and set to automatic if needed
   Set-Service -Name MpsSvc -StartupType Automatic
   Start-Service -Name MpsSvc
   ```

4. **Group Policy override**
   A domain GPO may override local settings. Verify the effective policy:

   ```powershell
   gpresult /h "$env:TEMP\gpresult.html"
   Start-Process "$env:TEMP\gpresult.html"
   ```

   Look under **Computer Configuration → Windows Firewall** for conflicting settings.

5. **Third-party security software**
   Some endpoint protection products disable or replace the built-in Windows Firewall. Check if a third-party firewall is active:

   ```powershell
   Get-NetFirewallProfile | Select-Object Name, Enabled
   ```

   If all profiles show `Enabled: False`, another product is likely managing the firewall.

### Log file exists but is empty

- Verify that logging is actually enabled:
  ```powershell
  Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed
  ```
- Confirm there is actual network traffic being processed by the firewall. On an idle system with no rules actively matching, the log may remain empty.

### Log file stops growing

- The file has reached its **maximum size** and is rotating. Increase `LogMaxSizeKilobytes`:
  ```powershell
  Set-NetFirewallProfile -Profile Domain, Private, Public -LogMaxSizeKilobytes 32768
  ```
- Alternatively, set up a scheduled task to archive and clear the log periodically.

### Access denied when reading the log

The default log path is under `system32`, which requires **Administrator** privileges to read. Either:

- Run PowerShell **as Administrator**
- Copy the log to a user-accessible location first:
  ```powershell
  Copy-Item "$env:windir\system32\LogFiles\Firewall\pfirewall.log" -Destination "$env:TEMP\pfirewall.log"
  Get-WindowsFirewallLog -LogFile "$env:TEMP\pfirewall.log"
  ```
- Use a custom log path that is readable by your account

### Custom log path not working

If you set a custom path, ensure:

1. The folder exists
2. `NT SERVICE\mpssvc` has **Write** access to the folder
3. The path does not contain environment variables when set via registry (use the expanded path)
