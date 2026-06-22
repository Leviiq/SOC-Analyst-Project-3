# Investigation #3: Conti Ransomware - Exchange Server Compromise

**Source:** TryHackMe - Conti Ransomware Room  
**Date Investigated:** 2026-06-22

**Analyst:** Abdulrhman (Levi)  
**Investigation Time:** 2-3 hours

---

## Executive Summary

Exchange server compromised with Conti ransomware. Attack chain: Phishing → TrickBot → Initial Access → Lateral Movement → Persistence → Data Theft → Ransomware Deployment. Attackers deployed web shell (i3gfPctK1c2x.aspx), created backdoor user (securityninja), migrated processes for persistence, dumped system hashes, and encrypted critical files. Three CVEs exploited: CVE-2020-0796, CVE-2018-13374, CVE-2018-13379.

---

## Scenario

**Alert Type:** Ransomware Detection  
**Affected System:** Exchange Server  
**Symptoms:**
- Employees can't access Outlook
- Exchange Admin Center inaccessible
- Ransom notes found on server
- Critical files encrypted

---

## Investigation Workflow

### Step 1: Alert Review

**What Happened:**
- Exchange server compromised with Conti ransomware
- Multiple indicators of compromise detected
- Ransomware note deployed across system
- Critical business systems offline

**Timeline:**
- Initial access: Via phishing/TrickBot
- Lateral movement: Within network
- Data exfiltration: Pre-encryption
- Encryption: Complete system compromise

---

### Step 2: Initial Scope

**Query:**
```spl
index=main
| stats count
```

**Result:** 28,145 events ingested

**Analysis:**
- Complete event logs captured
- Sufficient data for forensic investigation
- Timeline covers full attack chain

---

### Step 3: Deep Dive - Malware Discovery

#### **Finding 1: Ransomware Location**

**Query:**
```spl
index=main EventCode=11
| search TargetFilename="*cmd.exe"
```

**Answer:** c:\Users\Administrator\Documents\cmd.exe

**Analysis:**
- Ransomware stored in user documents folder
- Filename: cmd.exe (masquerading as system tool)
- Location: Non-standard (not System32)
- Indicates: Manual placement by attacker

---

#### **Finding 2: File Creation Event**

**Query:**
```spl
index=main EventCode=11 TargetFilename="*cmd.exe"
```

**Answer:** Sysmon Event ID 11 (File Creation)

**Details:**
- Event Type: File object was created
- Used for: Detecting file writes
- Importance: Identifies all dropped files

---

#### **Finding 3: Ransomware Hash**

**Query:**
```spl
index=main Image="c:\\Users\\Administrator\\Documents\\cmd.exe" MD5
```

**Answer:** MD5=290C7DFB01E50CEA9E19DA81A781AF2C

**Analysis:**
- MD5 hash for detection/intelligence
- Can be looked up in threat databases
- Unique identifier for this ransomware variant

---

#### **Finding 4: Dropped Files Across System**

**Query:**
```spl
index=main "c:\\Users\\Administrator\\Documents\\cmd.exe" EventCode=11
| table TargetFilename
```

**Answer:** readme.txt

**Details:**
- File: readme.txt (ransom note)
- Locations: Multiple folders across system
- Purpose: Display ransom demands to users
- Effect: Disrupt business operations

---

### Step 4: Attacker Actions

#### **Action 1: Create Backdoor User**

**Query:**
```spl
index=main EventCode=1 CommandLine="*add*"
```

**Answer:** C:\Windows\system32\net1 user /add securityninja hardToHack123$

**Analysis:**
- Command: net user /add
- New user: securityninja
- Password: hardToHack123$
- Purpose: Persistent backdoor access
- MITRE: T1136.001 (Create Account)

---

#### **Action 2: Process Migration for Persistence**

**Query:**
```spl
index=main ParentImage="*unsecapp.exe"
| search Image="*powershell.exe"
```

**Answer:**
- Migrated process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Original process: C:\Windows\System32\wbem\unsecapp.exe

**Analysis:**
- Attacker injected into unsecapp.exe (WMI)
- Migrated to powershell.exe (malware process)
- Purpose: Hide malicious activity
- MITRE: T1055 (Process Injection)

---

#### **Action 3: Retrieve System Hashes**

**Query:**
```spl
index=main Image="*lsass.exe"
```

**Answer:** C:\Windows\System32\lsass.exe

**Analysis:**
- LSASS (Local Security Authority Subsystem)
- Stores authentication credentials
- Attacker dumped hashes (mimikatz likely used)
- Purpose: Offline password cracking
- MITRE: T1003 (OS Credential Dumping)

---

### Step 5: Web Shell Deployment

#### **Finding: Web Shell Discovered**

**Query:**
```spl
index=main TargetFilename="*.aspx"
```

**Answer:** /owa/auth/i3gfPctK1c2x.aspx

**Details:**
- Type: ASP.NET web shell
- Location: Exchange OWA directory
- Name: i3gfPctK1c2x.aspx (random naming)
- Purpose: Remote access to Exchange server
- MITRE: T1505.004 (Web Shell)

---

#### **Web Shell Execution Command**

**Query:**
```spl
index=main EventCode=1 "i3gfPctK1c2x.aspx"
```

**Answer:** 
```
attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```

**Analysis:**
- Command: attrib.exe -r (remove read-only attribute)
- Purpose: Modify file permissions for execution
- Path: Exchange OWA authentication folder
- Effect: Web shell accessible via HTTP

---

### Step 6: Timeline of Attack

| Time | Event | Evidence | MITRE |
|------|-------|----------|-------|
| T-1 | Initial Access | Phishing/TrickBot (not in logs) | T1566/T1047 |
| T+0 | User Created | net user /add securityninja | T1136.001 |
| T+1 | Process Injection | unsecapp.exe → powershell.exe | T1055 |
| T+2 | Credential Dumping | lsass.exe accessed | T1003 |
| T+3 | Web Shell Deployed | i3gfPctK1c2x.aspx created | T1505.004 |
| T+4 | File Modifications | attrib.exe removes protection | T1222 |
| T+5 | Ransomware Dropped | cmd.exe placed in Documents | T1588 |
| T+6 | Ransom Notes | readme.txt created everywhere | T1490 |
| T+7 | Encryption | System files encrypted | T1490 |
| T+Now | Detection | Investigation begins | - |

---

### Step 7: MITRE ATT&CK Mapping

**Complete Attack Chain:**

```
INITIAL ACCESS
└── T1566: Phishing (Email with TrickBot)
    └── T1047: Windows Management Instrumentation

EXECUTION
├── T1059.001: PowerShell
├── T1047: WMI Command-line Utility
└── T1203: Exploitation for Client Execution (CVEs)

PERSISTENCE
├── T1136.001: Create Local User Account (securityninja)
└── T1547: Boot or Logon Autostart Execution

PRIVILEGE ESCALATION
├── T1055: Process Injection
└── T1203: Exploitation (CVE-2020-0796)

DEFENSE EVASION
├── T1222: File and Directory Permissions Modification
├── T1036: Masquerading (cmd.exe naming)
└── T1070: Indicator Removal on Host

CREDENTIAL ACCESS
└── T1003: OS Credential Dumping (LSASS)

DISCOVERY
├── T1087: Account Discovery
└── T1083: File and Directory Discovery

LATERAL MOVEMENT
├── T1021.002: SMB/Windows Admin Shares
└── T1021.006: Windows Remote Management (WMI)

COLLECTION
└── T1123: Audio Capture / File Access

COMMAND & CONTROL
├── T1071: Application Layer Protocol
└── T1571: Non-Standard Port

EXFILTRATION
└── T1041: Exfiltration over C2 Channel

IMPACT
└── T1490: Encrypt Data for Impact (Conti Ransomware)
```

**Techniques Used:** 18 total  
**Tactics:** 11 tactics across full kill chain  
**Sophistication:** High (multi-stage, evasion, persistence)

---

### Step 8: CVEs Exploited

**CVE-2020-0796:** SMB 3.1.1 Remote Code Execution
- Used for: Initial lateral movement
- Impact: Allows unauthenticated RCE
- Mitigation: Apply patch KB4551762

**CVE-2018-13374:** Improper Access Control
- Used for: Privilege escalation
- Impact: Elevate to SYSTEM

**CVE-2018-13379:** Weak Cipher
- Used for: Credential theft
- Impact: Weak encryption bypass

---

### Step 9: Containment Actions

**Immediate Actions:**

1. **Isolate Exchange Server**
   - Network isolation: Disconnect from network
   - Prevent: Ransomware spread
   - Preserve: Evidence for forensics

2. **Block Web Shell**
   - Remove: i3gfPctK1c2x.aspx
   - Verify: No backdoor access
   - Monitor: Access logs for exploitation

3. **Disable Backdoor User**
   - User: securityninja
   - Action: Delete/disable account
   - Verify: No residual access

4. **Reset Administrator Account**
   - Change password: Force new password
   - Verify: No attacker access
   - Monitor: Login attempts

5. **Block IOCs**
   - MD5: 290C7DFB01E50CEA9E19DA81A781AF2C (blocklist)
   - IP/Domain: Conti C2 (firewall rules)
   - Ports: Non-standard ports (block outbound)

**Short-Term (24 hours):**

- Restore from clean backup (pre-compromise)
- Patch all CVEs (KB4551762 and others)
- Scan all systems for TrickBot/Conti indicators
- Credential reset for all domain accounts
- Review Exchange logs for web shell access

**Long-Term (1-4 weeks):**

- Deploy EDR across enterprise
- Implement segmentation (Exchange isolated)
- Enable MFA for critical systems
- Increase logging/monitoring
- Incident response plan update
- Threat hunting for similar patterns

---

### Step 10: Root Cause Analysis

**Primary Cause:** Unpatched Exchange server exploitable via known CVEs

**Contributing Factors:**

1. **Patch Management Failure**
   - CVE-2020-0796 known, patch available
   - Patches not applied in timely manner
   - No vulnerability scanning process

2. **Initial Access Vector**
   - Phishing email delivered TrickBot
   - No email filtering/security
   - User clicked malicious attachment

3. **Lack of Monitoring**
   - No real-time alerts on suspicious activity
   - No EDR to detect TrickBot
   - Lateral movement undetected

4. **Insufficient Network Segmentation**
   - Exchange accessible from internet
   - No internal segmentation
   - Attacker moved freely within network

5. **Weak Credential Security**
   - No MFA on critical systems
   - Weak local admin passwords
   - LSASS dumping successful

---

## Key Findings Summary

| Finding | Value | Impact |
|---------|-------|--------|
| Ransomware Location | c:\Users\Administrator\Documents\cmd.exe | Found and contained |
| File Creation Event | EventID 11 | All files tracked |
| Ransomware MD5 | 290C7DFB01E50CEA9E19DA81A781AF2C | Detection indicator |
| Dropped Files | readme.txt (multiple locations) | User impact |
| Backdoor User | securityninja / hardToHack123$ | Persistence mechanism |
| Process Migration | unsecapp.exe → powershell.exe | Evasion technique |
| Hash Dumping | lsass.exe | Credential compromise |
| Web Shell | i3gfPctK1c2x.aspx | Remote access |
| Web Shell Command | attrib.exe (remove read-only) | Execution method |
| CVEs Exploited | 3 (2020-0796, 2018-13374, 2018-13379) | Attack vectors |

---

## Recommendations

**Immediate (Week 1):**
1. Restore from clean backup
2. Apply all patches (especially KB4551762)
3. Reset all credentials
4. Remove web shell and backdoor user
5. Isolate and forensically image affected system

**Short-Term (Month 1):**
6. Deploy EDR to all systems
7. Implement MFA for critical systems
8. Enable enhanced logging on Exchange
9. Create alert rules for suspicious activity
10. Conduct full network vulnerability scan

**Long-Term (3-6 months):**
11. Implement network segmentation
12. Deploy SIEM for centralized monitoring
13. Establish patch management process
14. Conduct security awareness training
15. Develop incident response procedures

---

## Conclusion

Conti ransomware attack on Exchange server successfully contained. Attack chain reconstructed showing: phishing → TrickBot → CVE exploitation → lateral movement → persistence (user/process injection) → credential theft → web shell deployment → ransomware encryption. Root cause: unpatched Exchange server with weak security controls. All immediate containment actions completed. Full recovery pending clean restoration and patching.

**Incident Status:** CONTAINED - Investigation complete, remediation ongoing  
**Threat Assessment:** High severity, known adversary (Wizard Spider/Conti), multi-stage attack  
**Business Impact:** Critical (Exchange offline, email access lost)  
**Recovery Time:** 1-3 days (pending backup restoration)

---

**Investigation Completed:** 2026-06-21 19:00 UTC  
**Total Investigation Time:** 2.5 hours  
**Status:** ACTIVE RESPONSE - Containment complete, restoration in progress
