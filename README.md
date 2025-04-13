<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/amanmavi7/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuser7” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-04-12T03:43:07.4978972Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "aman-threat-hun"
| where InitiatingProcessAccountName == "labuser7"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-12T03:25:27.824975Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/0bc120aa-8cbf-422d-9a9a-766fa19f1558">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-14.0.9.exe”. Based on the logs returned, at 2025-04-12T03:32:18.9980468Z, someone using the computer named "aman-threat-hun" and logged in as "labuser7" quietly launched a Tor Browser installer from their Downloads folder, using a command that let it install silently in the background, without showing any windows or asking questions.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "aman-threat-hun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1defd17a-0870-42ce-92bb-9a82bd464301">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user “labuser7” actually opened the tor browser. There was evidence that they did open it at 2025-04-12T03:33:14.0271008Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "aman-threat-hun"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/52f4993f-c1e2-49e2-8a32-e263d3e8ab75">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. On 2025-04-12T03:33:48.4163041Z, a computer named "aman-threat-hun" successfully made a network connection to the IP address 192.42.116.211 on port 9001. The connection was initiated by a program called tor.exe, which was running from a Tor Browser folder on the desktop of the user "labuser7". There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "aman-threat-hun"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1613070c-2237-45c5-ba0d-de38c906832d">

---

## Chronological Event Timeline 

2025-04-12T03:25:27Z onwards – A query initiated the threat hunt for the keyword “tor” across file events.


2025-04-12T03:32:18Z – labuser7 silently launched the Tor Browser installer (tor-browser-windows-x86_64-portable-14.0.9.exe) from the Downloads folder. This installation occurred without any GUI prompts, indicating intentional stealth.


2025-04-12T03:33:14Z – A process firefox.exe was executed, confirming that Tor Browser was opened. This was followed by other related processes like tor.exe and tor-browser.exe.


2025-04-12T03:33:48Z – A network connection was established by tor.exe to IP address 192.42.116.211 on port 9001, which is a well-known Tor port. This indicates successful Tor circuit establishment.


2025-04-12T03:43:07Z – A file named tor-shopping-list.txt was created on the desktop, likely indicating post-usage activity by the user, potentially to keep track of their Tor browsing or intentions.

---

## Summary

User labuser7 on the device aman-threat-hun downloaded and installed the Tor Browser using a silent installer to avoid detection or prompting.


The Tor Browser was successfully launched, and multiple supporting processes (tor.exe, firefox.exe) confirmed its operation.


A Tor network connection was successfully established, evidenced by a connection on port 9001 to a known Tor node.


The creation of tor-shopping-list.txt shortly after the browser use indicates the user may have been planning or recording activities tied to the Tor session.


The entire chain of events from installation to network activity and post-use documentation occurred within a span of less than 20 minutes, showing intent and technical awareness.

---

## Response Taken

TOR usage was confirmed on endpoint aman-threat-hun by the user labuser7. The device was isolated and the user's direct manager was notified.

---
