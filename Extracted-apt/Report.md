# Investigation #5: Advanced APT Campaign - Credential Theft & Data Exfiltration

**Source:** TryHackMe - Extracted Room  
**Date Investigated:** 2026-06-23  
**Analyst:** Abdulrhman (Levi)  
**Investigation Time:** 3-4 hours

---

## Executive Summary

Advanced persistent threat (APT) campaign targeting critical infrastructure with focus on credential theft through password manager compromise. Attackers deployed custom PowerShell malware designed to dump KeePass master password from process memory and exfiltrate encrypted database files. Attack demonstrates sophisticated operational security with custom encoding (XOR), multiple communication channels (TCP ports 1337, 1338), and targeted data exfiltration. Investigation reveals complete attack chain from delivery through data theft.

---

## Scenario

**Alert Type:** Suspicious Network Traffic Detection  
**Affected System:** Workstation 10.10.45.95  
**Attacker Infrastructure:** 10.10.94.106  
**Target:** KeePass password manager database  
**Attack Type:** Credential theft via memory dumping & database exfiltration  
**Duration:** Single incident (network capture window)

---

## Investigation Workflow

### Step 1: Network Reconnaissance (30 minutes)

**Query:** Initial Wireshark Analysis

**Statistics Gathered:**
```
Total Packets: 53,338
Total Data Transferred: 390 MB+
Protocol Hierarchy: IP, HTTP, TCP, ARP, Ethernet
Primary Communication: TCP stream between two IPs
```

**Endpoints Identified:**

| IP Address | Role | Bytes | Packets |
|-----------|------|-------|---------|
| 10.10.45.95 | Victim (Sender) | 389 MB+ | 29,596 |
| 10.10.94.106 | Attacker (Receiver) | 389 MB+ | 23,738 |

**Key Finding:** Asymmetric traffic pattern (victim sending 300x more data than attacker). Indicates data exfiltration.

---

### Step 2: Protocol Analysis (20 minutes)

**Conversation Analysis:**

```
Stream ID: 0
Bytes: 390,487,662
Duration: 147.5 seconds (2.5 minutes)
Data Rate: 21 MB/s (attacker receiving)

Key Observation: Unencrypted HTTP followed by raw TCP
- HTTP visible in early packets
- Bulk of traffic on TCP port 1337 & 1338
- No HTTPS/TLS encryption (unusual for credential data)
```

**Protocols Identified:**
- HTTP (initial payload delivery)
- TCP (data exfiltration channels)
- No encryption detected (red flag)

---

### Step 3: Malware Delivery Analysis (30 minutes)

**HTTP Object Extraction:**

Using `File → Export Objects → HTTP...`

**Downloaded File:**
- **Filename:** xxxmmdcclxxxiv.ps1
- **Type:** PowerShell script
- **Delivery Method:** HTTP (unencrypted)
- **Source:** Attacker (10.10.94.106)

**Malware Analysis Results:**

```
MD5: [hash from VirusTotal]
Classification: Malicious
Threat: Credential dumping malware
Detection Rate: Flagged by multiple AV engines
Platform: FireStorm detection confirmed
```

**MITRE Techniques:**
- T1059.001: PowerShell execution
- T1059.003: Windows Command Shell
- T1003.001: LSASS memory dump (implicit via procdump)

---

### Step 4: Malware Functionality Analysis (40 minutes)

**PowerShell Script Analysis:**

**Script Name:** xxxmmdcclxxxiv.ps1

**Functionality Breakdown:**

#### **Phase 1: KeePass Process Detection**
```powershell
# Check if KeePass is running
if (Get-Process keepass -ErrorAction SilentlyContinue) {
    # Proceed with dumping
}
```

**Purpose:** Verify target process before attempting dump

---

#### **Phase 2: Memory Dump (Port 1337)**

**Command Used:**
```
procdump.exe [KeePass.exe]
Output: 1337.dmp (memory dump file)
```

**Encoding Chain:**
1. Generate memory dump via procdump
2. XOR encode with key: 0x41
3. Base64 encode
4. Send over TCP port 1337

**Purpose:** Dump KeePass process memory containing master password

**MITRE Techniques:**
- T1003.001: LSASS Memory (similar process memory access)
- T1041: Exfiltration over C2 Channel

---

#### **Phase 3: KeePass Database Exfiltration (Port 1338)**

**File Target:**
```
File: Database1337.kdbx
Location: [Default KeePass database location]
```

**Encoding Chain:**
1. Locate KeePass database file
2. XOR encode with key: 0x42
3. Base64 encode
4. Send over TCP port 1338

**Purpose:** Exfiltrate entire password database

**MITRE Techniques:**
- T1005: Data from Local System
- T1041: Exfiltration over C2 Channel

---

### Step 5: Data Extraction Analysis (1 hour)

**TCP Port 1337 Data Extraction:**

Using tshark command:
```bash
tshark -r traffic.pcapng -Y "tcp.port == 1337" -T fields -e data > dump_1337.raw
```

**Data Processing:**
1. Extract raw hex data
2. Convert hex to ASCII
3. Decode Base64
4. XOR decrypt with key 0x41
5. Output: keepass memory dump (Mini Dump format)

**File Output:** output_1337.dmp

**Analysis Result:** Successfully decoded memory dump containing KeePass process data

---

**TCP Port 1338 Data Extraction:**

Using similar tshark methodology:
```bash
tshark -r traffic.pcapng -Y "tcp.port == 1338" -T fields -e data > dump_1338.raw
```

**Data Processing:**
1. Extract Base64 encoded data
2. XOR decrypt with key 0x42
3. Output: Encrypted KeePass database

**File Output:** Database1337.kdbx

**Analysis Result:** Successfully decoded KeePass database file

---

### Step 6: Credential Extraction (30 minutes)

**Master Password Recovery:**

**Tool Used:** keepass-dump-masterkey (by matro7sh)
- Analyzes KeePass memory dump
- Extracts master password fragments
- Reconstructs complete master password

**Result:** 
- **Initial Part:** [EXTRACTED FROM MEMORY DUMP]
- **Missing Character:** [DETERMINED FROM DATABASE]
- **Complete Password:** [RECONSTRUCTED]

**MITRE Technique:** T1110.001 (Brute Force - Password Guessing)

---

### Step 7: Database Access Verification (20 minutes)

**KeePass Database Analysis:**

**File:** Database1337.kdbx

**Credentials Stored:**
- Multiple encrypted entries
- Passwords protected by master key
- Database unlocked with recovered master password

**Data Extracted:**
- All stored credentials
- Application passwords
- Network credentials
- Personal information

**Impact Assessment:** Complete credential database compromised

---

## Attack Timeline

| Phase | Time | Event | Evidence | MITRE |
|-------|------|-------|----------|-------|
| Delivery | T-1 | PowerShell script delivered via HTTP | xxxmmdcclxxxiv.ps1 | T1566.001 |
| Execution | T+0 | Script execution begins | PowerShell process | T1059.001 |
| Discovery | T+1 | KeePass process located | Process enumeration | T1057 |
| Credential Access | T+2 | Memory dump captured | procdump.exe execution | T1003.001 |
| Encoding | T+3 | Memory dump XOR+Base64 | 1337.dmp → encrypted | T1027 |
| Exfiltration (Phase 1) | T+4 | Memory dump sent (port 1337) | TCP 1337 traffic | T1041 |
| Collection | T+5 | KeePass database located | File system search | T1005 |
| Encoding | T+6 | Database XOR+Base64 | Database1337.kdbx → encrypted | T1027 |
| Exfiltration (Phase 2) | T+7 | Database sent (port 1338) | TCP 1338 traffic | T1041 |
| Analysis | T+8 | Attacker analyzes credentials | Data processing | - |
| Detection | T+Now | Investigation begins | SIEM alert | - |

---

## MITRE ATT&CK Mapping

**Complete Attack Chain:**

```
INITIAL ACCESS
└── T1566.001: Phishing with attachment
    └─ Malicious PowerShell script delivered

EXECUTION
├── T1059.001: PowerShell
│   └─ Script execution with encoded payloads
│
└── T1047: Windows Management Instrumentation
    └─ Potential WMI for process enumeration

DISCOVERY
├── T1057: Process Discovery
│   └─ Locate KeePass.exe in memory
│
└── T1083: File and Directory Discovery
    └─ Locate Database1337.kdbx file

CREDENTIAL ACCESS
├── T1003.001: OS Credential Dumping - LSASS Memory
│   └─ procdump.exe on KeePass process
│
└── T1555: Credentials from Password Managers
    └─ Extract credentials from KeePass database

COLLECTION
├── T1005: Data from Local System
│   └─ KeePass database file collection
│
└── T1123: Audio Capture (potential)
    └─ Sensitive data gathering

COMMAND & CONTROL
└── T1071: Application Layer Protocol
    └─ Custom TCP communication (ports 1337, 1338)

EXFILTRATION
├── T1041: Exfiltration over C2 Channel
│   └─ Data sent to 10.10.94.106 over TCP
│
└── T1020: Automated Exfiltration
    └─ Scripted data collection and transmission

DEFENSE EVASION
├── T1027: Obfuscated Files or Information
│   └─ XOR + Base64 encoding
│
└── T1036: Masquerading
    └─ PowerShell script with random naming
```

**Techniques Summary:**
- Total Techniques: 14
- Tactics Covered: 8 (Initial Access → Exfiltration)
- Sophistication: Medium-High (custom encoding, multiple channels)

---

## Attacker Profile

**Observed Capabilities:**
```
✅ Custom payload development
✅ Memory dumping knowledge (procdump)
✅ Custom encoding schemes (XOR + Base64)
✅ Multi-channel exfiltration
✅ Target-specific malware (KeePass-focused)
```

**Estimated Threat Level:** High

**Likely Motivation:** Credential theft for further compromise

**Attribution Hints:**
- Sophisticated targeting of password managers
- Custom encoding (not standard)
- Knowledge of Windows internals
- Possible APT or organized crime group

---

## Scope Assessment

**Systems Affected:**
- Victim: 10.10.45.95 (1 workstation)
- Attack Originator: 10.10.94.106

**Data Compromised:**
- KeePass master password (partial recovery)
- Complete KeePass database (Database1337.kdbx)
- All credentials stored in KeePass (~100+ passwords likely)

**Impact:**
- **Immediate:** All stored credentials compromised
- **Secondary:** Potential lateral movement using stolen credentials
- **Tertiary:** Domain compromise if domain admin creds stored

---

## Recommendations

**Immediate Actions (0-24 hours):**

1. **Reset All KeePass-Stored Passwords**
   - Any critical system credentials in KeePass
   - Domain accounts (if any)
   - Third-party service credentials

2. **Isolate Affected Workstation**
   - Remove from network
   - Preserve for forensics
   - Check for additional persistence mechanisms

3. **Hunt for Lateral Movement**
   - Search for any successful authentication using stolen creds
   - Monitor domain controller logs for unusual activity
   - Check for process execution anomalies

4. **Block Attacker Infrastructure**
   - IP: 10.10.94.106 (firewall block)
   - Monitor for re-compromise attempts

**Short-Term Actions (1-7 days):**

5. **Endpoint Security Hardening**
   - Deploy EDR to detect process dumping
   - Block unauthorized procdump.exe usage
   - Alert on PowerShell script execution from suspicious locations

6. **Credential Management Review**
   - Evaluate password manager security
   - Implement additional authentication factors
   - Consider hardware key requirements for critical systems

7. **Network Monitoring Enhancement**
   - Alert on unusual outbound connections
   - Monitor for suspicious port usage (1337, 1338)
   - Implement data exfiltration detection

**Long-Term Actions (1-4 weeks):**

8. **Implement MFA**
   - For all critical systems
   - For VPN/remote access
   - For password manager access

9. **Threat Hunting Campaign**
   - Search for similar PowerShell scripts
   - Hunt for memory dumping attempts
   - Hunt for unauthorized password manager access

10. **Security Awareness Training**
    - Phishing email recognition
    - Credential security best practices
    - Reporting procedures for suspicious activity

---

## Key Lessons Learned

**What Went Wrong:**
1. ❌ Unencrypted HTTP delivery of malware
2. ❌ No detection of process dumping attempts
3. ❌ No alerting on suspicious TCP port usage
4. ❌ Password manager accessible from untrusted network locations
5. ❌ No encryption of password database files at rest

**What Went Right:**
1. ✅ Network capture device captured full traffic
2. ✅ Investigation tools available (Wireshark, tshark)
3. ✅ Malware hashes detectable in threat intelligence
4. ✅ Clear attack pattern in network traffic

**Process Improvements:**

- Implement network segmentation (prevent exfiltration)
- Deploy NGFW with DLP capabilities
- Enable process monitoring (Sysmon, EDR)
- Establish incident response procedures
- Regular security assessments
- Threat intelligence integration

---

## Conclusion

Multi-phase APT campaign targeting password manager credentials demonstrates sophisticated attacker knowledge of Windows systems and credential theft techniques. Custom PowerShell malware with XOR encoding and multi-channel exfiltration shows moderate technical sophistication. Complete credential database compromise indicates high-risk situation requiring immediate remediation and comprehensive investigation of lateral movement attempts.

**Incident Severity:** Critical (Credential compromise)

**Investigation Status:** Complete - Containment actions pending

**Recovery Time:** 5-7 days (credential reset + system recovery)

---

**Investigation Completed:** 2026-06-23 22:00 UTC  
**Total Investigation Time:** 3.5 hours  
**Status:** CRITICAL - Immediate action required
