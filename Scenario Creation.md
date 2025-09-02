# Threat Event (Unauthorized 7-Zip Usage)
**Unauthorized 7-Zip Installation and Use for Data Exfiltration**

---

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the standalone 7-Zip executable (`7zr.exe`) from: https://www.7-zip.org/download.html  
2. Stage fake confidential files on the Desktop (e.g., `EmployeeRecords_pwncrypt.csv`, `ProjectList_pwncrypt.csv`, `CompanyFinancials_pwncrypt.csv`).  
3. Compress the files into an archive using 7-Zip:  
   ```7zr.exe a staged-data.7z <target files>```  
4. Create a password-protected archive to simulate secure exfiltration:  
   ```7zr.exe a -pSuperSecret123 -mhe=on staged-data-encrypted.7z <target files>```  
5. Move the encrypted archive into the Downloads folder to simulate staging for exfiltration.  
6. (Optional) Simulate uploading the archive by opening cloud storage sites (e.g., Google Drive, Dropbox).  
7. Delete the archive and staged files to simulate cleanup.  

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                                 |
|----------------------|---------------------------------------------------------------------------------|
| **Name** | DeviceProcessEvents |  
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |  
| **Purpose** | Used to detect execution of `7zr.exe` and confirm command-line arguments for archive creation and encryption. |

| **Parameter**       | **Description**                                                                 |
|----------------------|---------------------------------------------------------------------------------|
| **Name** | DeviceFileEvents (optional) |  
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |  
| **Purpose** | May detect creation/movement/deletion of `.7z` archives or staged files. In this lab, no file events appeared. |

| **Parameter**       | **Description**                                                                 |
|----------------------|---------------------------------------------------------------------------------|
| **Name** | DeviceNetworkEvents (optional) |  
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |  
| **Purpose** | May detect connections to cloud storage services if exfiltration is simulated via browser. Not observed in this lab. |

---

## Related Queries:
```kql
// Detect execution of 7-Zip commands (archive creation / password protection)
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc

// Detect password-protected archive creation (-p / -mhe)
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| where ProcessCommandLine has_any (" -p", "-mhe=on")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

// Detect archives referenced in command lines (.7z output)
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("7zr.exe","7z.exe")
| where ProcessCommandLine has ".7z"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

// Optional: Detect file events (not observed in this lab)
DeviceFileEvents
| where DeviceName == "dbwindowsadmin"
| where FileName has ".7z"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc

// Optional: Detect cloud storage access (not observed in this lab)
DeviceNetworkEvents
| where DeviceName == "dbwindowsadmin"
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe")
| where RemoteUrl has_any ("drive.google.com","dropbox.com")
| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```
## Created By
- **Author Name**: [Your Name Here]  
- **Author Contact**: [LinkedIn or GitHub]  
- **Date**: August 30, 2025  

## Validated By
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

## Additional Notes
- In this lab, **DeviceProcessEvents** provided the primary evidence of 7-Zip execution and archive creation.  
- **DeviceFileEvents** and **DeviceNetworkEvents** were included for completeness but did not show results in this environment.  
- Process command-line arguments (e.g., `-p`, `-mhe=on`) were sufficient to confirm encrypted archive creation.  

## Revision History
| **Version** | **Changes**                             | **Date**         | **Modified By**     |
|-------------|-----------------------------------------|------------------|---------------------|
| 1.0         | Initial 7-Zip exfiltration draft report | August 30, 2025  | [Your Name Here]    |

