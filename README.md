# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/kayosituyo/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what seems like the user “kaybond” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop at '2026-08-18T01:02:02.2472425Z' and the creation of a file called “tor-shopping-list.txt”.These events began at: '2026-08-18T00:25:20.4331338Z'.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "corp-guy7-tuy"
| where InitiatingProcessAccountName == "kaybond"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-08-18T00:25:20.4331338Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName

```
<img width="1212" alt="image" src="https://github.com/kayosituyo/threat-hunting-scenario-tor/blob/main/DeviceProcessEvents.jpeg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandline  that contained the string “tor-browser-windows”. Based on the log returned, at 2026-08-18T00:48:05.8046937Z, a user 'kaybond' launched a portable Tor Browser executable from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "corp-guy7-tuy"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/kayosituyo/threat-hunting-scenario-tor/blob/main/DeviceProcessEvents2.jpeg">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “kaybond” opened the tor browser. There was evidence that they did open it at 2026-08-18T00:49:06.8674796Z. There were several other instances of firefox.exe(Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "corp-guy7-tuy"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/kayosituyo/threat-hunting-scenario-tor/blob/main/DeviceProcessEvents3.jpeg">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known Tor ports. At 2026-08-18T00:49:36.2714441Z, the account 'kaybond' on 'corp-guy7-tuy' successfully established a connection to 127.0.0.1 (localhost) on port 9150. The connection was initiated by Firefox, which is part of the Tor Browser installation. Tor Browser’s Firefox process successfully connected to the local Tor service running on port 9150. This is consistent with Tor Browser establishing its local connection for Tor network traffic.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "corp-guy7-tuy"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, Account=InitiatingProcessAccountName, ActionType, RemoteIP,RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/kayosituyo/threat-hunting-scenario-tor/blob/main/DeviceNetworkEvents.jpeg">

---

## Chronological Event Timeline 

### 1.   8:40:42 PM — File Renamed
  tor-browser-windows-x86_64-portable-15.0.19.exe — C:\Users\kaybond\Downloads
 → Installer file finalized in Downloads folder, indicating the download had just               completed.
    
### 2.   8:48:05 PM — Process Created
  tor-browser-windows-x86_64-portable-15.0.19.exe /S (launched from Downloads)
  → The /S flag triggers a silent install with no UI prompts — consistent with an               intentional, low-visibility install rather than a default interactive one.
       
### 3.  8:48:17 PM — File Created (x3)
   tor.txt, Torbutton.txt, Tor-Launcher.txt — ...\Tor Browser\Browser\TorBrowser\Docs\Licenses
 → License files extracted — confirms the installer began unpacking the Tor Browser package to the Desktop.
 
### 4.  8:48:18 PM — File Created
 tor.exe — ...\Tor Browser\Browser\TorBrowser\Tor\tor.exe
 → The core Tor client binary was written to disk.
 
### 5.  8:48:22 PM — File Created
 Tor Browser.lnk — C:\Users\kaybond\Desktop\Tor Browser
 → Desktop shortcut created — marks completion of the silent install (~17 seconds total).
 
### 6.  8:49:06 – 8:49:07 PM — Process Created (x2)
 firefox.exe — ...\Tor Browser\Browser\firefox.exe
 → Tor Browser (Firefox-based) launched for the first time, ~44 seconds after install completed.
 
### 7.  8:49:14 PM — File Created
 storage.sqlite — ...\TorBrowser\Data\Browser\profile.default
 → Browser profile initialized on first run.
 
### 8.  8:49:15 – 8:49:23 PM — Process Created (x8)
 firefox.exe child processes (gpu, rdd, utility, and initial tab processes)
 → Normal Firefox/Tor Browser multi-process startup sequence — browser finishing initialization.
 
### 9.  8:49:19 PM — Process Created
 tor.exe -f torrc ... SocksPort 127.0.0.1:9150, ControlPort 127.0.0.1:9151
 → The Tor client process started with its local SOCKS proxy (9150) and control port (9151) configured — the mechanism that routes browser traffic over the Tor network.
 
### 10.  8:49:19 PM — File Created
 storage-sync-v2.sqlite — ...\TorBrowser\Data\Browser\profile.default
 → Additional browser profile data written.
 
### 11.  8:49:36 PM — Connection Success
 firefox.exe → 127.0.0.1:9150 (localhost)
 → Confirms Tor Browser successfully connected to the local Tor SOCKS proxy — the browser was actively routing traffic through the Tor network, not just installed.
 
### 12.  8:49:37 – 8:55:53 PM — Process Created (x11)
 firefox.exe content/tab processes (tabs 11 through 20, plus one utility process)
 → Sustained, active browsing session — at least 20 distinct tab/content processes spawned over ~6.5 minutes, indicating deliberate, extended use rather than a brief or accidental launch.
 
###13.  9:02:02 PM — File Created (x2)
 tor-shopping-list.txt → C:\Users\kaybond\Documents
 tor-shopping-list.lnk → ...\AppData\Roaming\Microsoft\Windows\Recent
 → A text file with a suggestive name was created in Documents and simultaneously registered in Recent Items, indicating the user created and opened it during or immediately after the Tor session.


---

## Summary

On August 17, 2026, the account kaybond on device corp-guy7-tuy downloaded and silently installed a portable copy of Tor Browser (version 15.0.19), launched it within roughly a minute of installation, and successfully connected to the Tor network via the browser's local SOCKS proxy. The session was not brief or incidental — at least 20 browser tab/content processes were spawned over the following six and a half minutes, indicating sustained, active use. Shortly after the browsing session, a file named "tor-shopping-list.txt" was created in the user's Documents folder and simultaneously logged in Recent Items, indicating the user created and opened it around the same time.
The use of the silent-install flag (/S) and a portable, self-contained build (rather than a standard installer requiring admin rights) are both consistent with an attempt to install Tor Browser with minimal visibility. Tor usage on a corporate endpoint is a significant finding on its own, since it anonymizes and encrypts network traffic in a way that bypasses standard web content filtering, DLP, and network monitoring controls — independent of what the user actually did once connected.


---

## Response Taken

TOR usage was confirmed on the endpoint `corp-guy7-tuy` by the user `kaybond`. The device was isolated, and the user's direct manager was notified.

---
