# Threat Hunting 7-Zip Report

- [Scenario Creation](#)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)  
- EDR Platform: Microsoft Defender for Endpoint  
- Kusto Query Language (KQL)  
- 7-Zip Portable (`7zr.exe`)  


## Scenario

Management suspects that some employees may be using unauthorized utilities (such as portable archivers) to compress and stage data for potential exfiltration. A recent security advisory noted that 7-Zip portable can be run without administrative privileges, bypassing corporate application controls. Additionally, IT has observed suspicious attempts at compressing large folders on monitored endpoints.  

The goal is to detect any unauthorized 7-Zip usage and analyze related security incidents to mitigate potential data loss. If any use of 7-Zip is found, notify management.  

### High-Level 7-Zip-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for 7-Zip execution (`7zr.exe` or `7z.exe`) with archive creation commands.  
- **Check `DeviceProcessEvents`** for password-protected archive creation (flags `-p`, `-mhe`).  
- **Check `DeviceFileEvents`** for `.7z` archive files created, moved, or deleted (optional, may not appear).  
- **Check `DeviceNetworkEvents`** for possible exfiltration attempts if archives are uploaded via browsers (optional).  

### 1. Searched the `DeviceProcessEvents` Table

Confirmed execution of `7zr.exe` by user `dbwindowsadmin` from the Downloads folder.  
The process telemetry showed usage of the `a` (add) command to compress files into archives.  

**Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

### 2. Detected Password-Protected Archive Creation

Process telemetry revealed that `7zr.exe` was executed with the `-p` and `-mhe=on` arguments, confirming creation of a password-protected and header-encrypted archive (`staged-data-encrypted.7z`).  

**Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| where ProcessCommandLine has_any (" -p", "-mhe=on")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### 3. Searched for `.7z` Archive References in Command Line

Additional process logs showed `.7z` output files referenced in command lines, validating that archives were successfully created.  

**Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| where ProcessCommandLine has ".7z"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### 4. Optional File and Network Telemetry

- `DeviceFileEvents` was queried for creation/movement/deletion of `.7z` files, but **no events were observed** in this lab environment.  
- `DeviceNetworkEvents` was queried for potential cloud upload activity (Google Drive, Dropbox), but **no events were observed**.  

**File query used:**
```kql
DeviceFileEvents
| where DeviceName == "dbwindowsadmin"
| where FileName has ".7z"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

## Chronological Event Timeline

### 1. Process Execution – Archive Creation
- **Event:** `7zr.exe` executed by `dbwindowsadmin`.  
- **Action:** Compression initiated using the `a` (add) command.  
- **Command:** `7zr.exe a staged-data.7z ...`  

---

### 2. Process Execution – Encrypted Archive Creation
- **Event:** `7zr.exe` executed with encryption flags.  
- **Action:** Password-protected archive created.  
- **Command:** `7zr.exe a -pSuperSecret123 -mhe=on staged-data-encrypted.7z ...`  

---

### 3. Archive Staging
- **Event:** Archive moved into the Downloads folder.  
- **Action:** Staging for potential exfiltration confirmed via process telemetry.  

---

*Note: File creation/deletion telemetry (`DeviceFileEvents`) was expected but not observed. Process telemetry (`DeviceProcessEvents`) alone provided sufficient evidence of archive creation and encryption.*  

## Summary

The user `dbwindowsadmin` on endpoint `dbwindowsadmin` executed 7-Zip portable (`7zr.exe`) to compress and encrypt files outside of sanctioned corporate policy.  

Evidence collected included:  

- **Process execution** of `7zr.exe` with `a` (add) command.  
- **Process arguments** confirming password-protected archive creation (`-p`, `-mhe=on`).  
- **Archive staging** in the Downloads folder.  

This sequence of events confirms unauthorized use of 7-Zip to prepare potentially sensitive data for exfiltration.  

## Response Taken

Unauthorized 7-Zip usage was confirmed on endpoint `dbwindowsadmin`.  
The following response actions were taken:  

- The device was flagged for review by the SOC team.  
- Management was notified of the confirmed 7-Zip activity.  
- Recommendations were made to restrict portable application usage and implement stronger application whitelisting controls.  

## Created By
- **Author Name**: Daniel Botomogno  
- **Author Contact**: https://www.linkedin.com/in/daniel-botomogno-fsri-flmi-35992588/  
- **Date**: August 30, 2025  

## Validated By
- **Reviewer Name**:  N/A
- **Reviewer Contact**: N/A
- **Validation Date**:  N/A

## Additional Notes
- In this lab, **DeviceProcessEvents** provided the primary evidence of 7-Zip execution and archive creation.  
- **DeviceFileEvents** and **DeviceNetworkEvents** did not show results in this environment but queries were included for completeness.  
- Process command-line arguments (e.g., `-p`, `-mhe=on`) were sufficient to confirm encrypted archive creation.  

## Revision History
| **Version** | **Changes**                             | **Date**         | **Modified By**   |
|-------------|-----------------------------------------|------------------|-------------------|
| 1.0         | Initial 7-Zip exfiltration draft report | August 30, 2025  | Daniel Botomogno  |
