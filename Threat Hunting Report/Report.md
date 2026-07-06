# Threat Hunting Report - Week 3: Detection Engineering
**Date:** 2026-06-24  
**Analyst:** Abdulrhman (Levi)  
**Duration:** Day 15-17  
**Report Type:** Proactive Threat Hunting Exercise

---

## Executive Summary

Proactive threat hunting campaign focused on identifying lateral movement, credential dumping, and data exfiltration activities across the network. Three hypothesis-driven hunts conducted to detect advanced attack tactics using Sysmon event logs and Splunk queries. Findings reveal both legitimate administrative activity and suspicious patterns requiring further investigation. New detection rules recommended for continuous monitoring.

---

## Hunting Methodology

**Approach:** Hypothesis-Driven Hunting
- Develop threat hypothesis based on known attack patterns
- Design targeted Splunk queries
- Analyze results for benign vs suspicious activity
- Recommend actionable detection rules

**Data Sources:** Sysmon EventCode logs
- EventCode 1: Process Creation
- EventCode 10: Process Access (LSASS targeting)
- EventCode 11: File Creation (Data staging)

**Hunting Objectives:**
1. Detect lateral movement tool usage
2. Identify credential dumping attempts
3. Find data staging/exfiltration preparation

---

# HYPOTHESIS 1: Lateral Movement via Legitimate Tools

## Hypothesis Statement

**"Attackers may be using legitimate Windows administration tools (PSExec, WMIC) for lateral movement from non-privileged user accounts."**

---

## Query Design

```spl
index=sysmon EventCode=1 Image="*psexec.exe" OR Image="*wmic.exe"
| where User!="SYSTEM" AND User!="Administrator"
```

**Query Logic:**
- **index=sysmon:** Search Sysmon process creation logs
- **EventCode=1:** Process creation events only
- **Image="*psexec.exe" OR Image="*wmic.exe":** Search for these specific tools
- **where User!="SYSTEM" AND User!="Administrator":** Filter for non-privileged users

---

## Expected Findings

### Benign Results (Normal Activity)

```
1. Legitimate Administrator Activity
   ├─ User: "Domain\AdminUser"
   ├─ Tool: psexec.exe
   ├─ Target: Authorized servers
   ├─ Time: Business hours (9-5)
   └─ Frequency: Scheduled maintenance

2. System Administrators
   ├─ User: "Domain\ITSupport"
   ├─ Tool: wmic.exe
   ├─ Purpose: Remote server management
   ├─ Documentation: Tickets exist
   └─ Approved: Change management

3. Scheduled Tasks
   ├─ User: "SYSTEM"
   ├─ Tool: wmic.exe
   ├─ Purpose: Legitimate automation
   ├─ Context: Batch jobs
   └─ Expected: Known processes
```

### Suspicious Results (Indicators of Compromise)

```
1. Non-Privileged User Executing PSExec
   ├─ User: "Domain\JohnDoe" (regular employee)
   ├─ Tool: psexec.exe
   ├─ Target: Domain controller or sensitive server
   ├─ Time: After-hours (2 AM)
   └─ Red Flags: 
       - User shouldn't have access
       - Unexpected tool usage
       - Lateral movement pattern
       - Timing suspicious

2. Suspicious WMIC Usage
   ├─ User: "Domain\Guest" or temp account
   ├─ Tool: wmic.exe
   ├─ Process Path: Non-standard location (C:\Temp\)
   ├─ Frequency: Repeated connections to multiple servers
   └─ Red Flags:
       - Guest accounts shouldn't use WMIC
       - Multiple server targeting
       - Reconnaissance pattern

3. Parent Process Anomaly
   ├─ Parent: powershell.exe (suspicious)
   ├─ Child: psexec.exe
   ├─ Context: No documented reason
   └─ Red Flags:
       - PowerShell parent unusual for PSExec
       - Indicates script-based attack
       - Potential lateral movement automation
```

---

## Analysis & Findings

### What We're Looking For

**Lateral Movement Indicators:**
```
✅ Tool Execution: PSExec or WMIC
✅ User Context: Non-SYSTEM, Non-Administrator
✅ Target: Multiple servers (hop-by-hop)
✅ Timing: Outside business hours
✅ Frequency: Multiple attempts in short timeframe
✅ Parent Process: Unusual (PowerShell, cmd, etc)
```

### Findings Interpretation

**GREEN (Benign):**
```
- Documented administrators using tools
- Business hours execution
- Single target servers
- Expected parent processes
- Change control tickets exist
```

**YELLOW (Suspicious):**
```
- Non-documented user execution
- After-hours execution
- Multiple targets in sequence
- Unexpected parent processes
- No tickets or documentation
```

**RED (High Risk):**
```
- Low-privileged users executing tools
- Rapid server-to-server movement
- Guest/temp accounts involved
- Obvious obfuscation attempts
- Pattern matches known lateral movement
```

---

## Recommendations

**If Benign Findings Detected:**
- Document legitimate tool usage
- Create whitelist for future hunting
- Baseline for normal activity
- No action required

**If Suspicious Findings Detected:**
1. **Immediate Investigation:**
   - Correlate with other EventCodes
   - Check authentication logs
   - Verify with user/manager
   - Check for related process execution

2. **Containment:**
   - Monitor account closely
   - Check for privilege escalation
   - Review data accessed
   - Check for credential theft

3. **Root Cause Analysis:**
   - Determine if compromised account
   - Identify initial access vector
   - Check for persistence mechanisms
   - Review lateral movement scope

---

# HYPOTHESIS 2: Credential Dumping via LSASS Access

## Hypothesis Statement

**"Attackers may be attempting to dump credentials from LSASS process memory using suspicious access patterns."**

---

## Query Design

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1010
| where SourceImage!="*svchost.exe"
```

**Query Logic:**
- **index=sysmon:** Search Sysmon process access logs
- **EventCode=10:** Process access events (suspicious memory reads)
- **TargetImage="*lsass.exe":** Target process is LSASS
- **GrantedAccess=0x1010:** Suspicious access rights (read memory)
- **where SourceImage!="*svchost.exe":** Exclude legitimate system process

---

## Expected Findings

### Benign Results (Normal Activity)

```
1. System Processes
   ├─ Source: svchost.exe (EXCLUDED by query)
   ├─ Access: Legitimate memory reads
   ├─ Frequency: Regular
   └─ Risk: None (filtered out)

2. Security Software
   ├─ Source: "antivirus.exe" or security agent
   ├─ Access: Legitimate monitoring
   ├─ Purpose: System protection
   └─ Risk: None (expected)

3. Windows Diagnostics
   ├─ Source: "diagnostic.exe"
   ├─ Access: Legitimate analysis
   ├─ Purpose: System health monitoring
   └─ Risk: None (expected)
```

### Suspicious Results (Indicators of Compromise)

```
1. Mimikatz Process
   ├─ Source: "mimikatz.exe"
   ├─ Target: lsass.exe
   ├─ Access: 0x1010 (VM_READ)
   ├─ Context: Credential dumping
   └─ Risk: CRITICAL

2. Custom Executable
   ├─ Source: "unknown.exe" (C:\Temp\)
   ├─ Target: lsass.exe
   ├─ Access: 0x1010
   ├─ Parent: powershell.exe or cmd.exe
   └─ Risk: CRITICAL

3. PowerShell Process
   ├─ Source: "powershell.exe"
   ├─ Target: lsass.exe
   ├─ Access: 0x1010
   ├─ Command: Contains suspicious keywords
   └─ Red Flags:
       - PowerShell shouldn't access LSASS
       - Script-based credential theft
       - Advanced attacker technique

4. Unexpected System Process
   ├─ Source: "rundll32.exe" or "explorer.exe"
   ├─ Target: lsass.exe
   ├─ Access: 0x1010
   ├─ Context: No legitimate reason
   └─ Risk: HIGH

5. Multiple Rapid Accesses
   ├─ Pattern: Multiple processes in short timeframe
   ├─ Target: All to lsass.exe
   ├─ Frequency: Seconds apart
   └─ Red Flags:
       - Orchestrated attack
       - Automated credential harvesting
       - Multiple tools attempting dump
```

---

## Analysis & Findings

### What We're Looking For

**Credential Dumping Indicators:**
```
✅ Target: LSASS process specifically
✅ Access Level: 0x1010 (read memory)
✅ Source: Non-system processes
✅ Tools: Mimikatz, procdump, custom tools
✅ Timing: Unusual (off-hours, rapid succession)
✅ Parent: PowerShell, cmd, rundll32 (suspicious parents)
```

### Access Code Explanation (0x1010)

```
0x1010 in hex = 4112 in decimal
Meaning: PROCESS_VM_READ permission
Purpose: Read process virtual memory
Used By: Credential dumping tools to extract passwords
Normal Use: Only system processes should request this
```

### Findings Interpretation

**GREEN (Benign):**
```
- Antivirus/security software only
- Windows system processes (svchost)
- Rare, documented legitimate tools
- Business hours execution
```

**YELLOW (Suspicious):**
```
- Unexpected processes accessing LSASS
- Unusual parent-child relationships
- Off-hours access patterns
- Known security tool (but not expected to run)
```

**RED (Critical):**
```
- Mimikatz or credential dumping tools
- Custom/unknown executables
- PowerShell accessing LSASS
- Rapid sequential accesses
- Multiple tools targeting LSASS
```

---

## Recommendations

**If Benign Findings Detected:**
- Document expected tools
- Create exclusion list
- Monitor for changes
- No action required

**If Suspicious Findings Detected:**
1. **IMMEDIATE RESPONSE:**
   - Kill suspicious process immediately
   - Isolate affected computer
   - Force password reset for all users logged in
   - Check for additional compromises

2. **FORENSIC INVESTIGATION:**
   - Capture memory dump
   - Preserve disk image
   - Correlate with other events
   - Determine scope of credential exposure

3. **DAMAGE ASSESSMENT:**
   - Identify what credentials were exposed
   - Check for lateral movement using stolen creds
   - Review all systems accessed by compromised accounts
   - Check for privilege escalation attempts

---

# HYPOTHESIS 3: Data Staging Before Exfiltration

## Hypothesis Statement

**"Attackers may be staging large amounts of data in temporary directories (C:\Temp) in ZIP files before exfiltration."**

---

## Query Design

```spl
index=sysmon EventCode=11 TargetFilename="C:\\Temp\\*.zip"
| stats sum(FileSize) by User | where sum > 500000000
```

**Query Logic:**
- **index=sysmon:** Search Sysmon file creation logs
- **EventCode=11:** File creation events only
- **TargetFilename="C:\\Temp\\*.zip":** Only ZIP files in C:\Temp folder
- **stats sum(FileSize) by User:** Aggregate total size by user
- **where sum > 500000000:** Filter for over 500 MB (suspicious volume)

---

## Expected Findings

### Benign Results (Normal Activity)

```
1. Software Installation
   ├─ User: "SYSTEM"
   ├─ File: installer_temp.zip
   ├─ Size: 100-200 MB (single file)
   ├─ Frequency: During updates
   └─ Risk: None

2. Legitimate Backup
   ├─ User: "Domain\BackupAdmin"
   ├─ File: backup_2024-06-24.zip
   ├─ Size: 400-500 MB (occasional)
   ├─ Purpose: Documented backup
   └─ Risk: None

3. Download Extraction
   ├─ User: "Domain\Developer"
   ├─ File: project_archive.zip
   ├─ Size: 250 MB
   ├─ Context: Development work
   └─ Risk: None
```

### Suspicious Results (Indicators of Compromise)

```
1. Large Volume Aggregation
   ├─ User: "Domain\NormalUser"
   ├─ Total Size: 1.5 GB across multiple ZIPs
   ├─ Timeframe: Created within 1 hour
   ├─ Frequency: Multiple files (10+)
   └─ Red Flags:
       - User shouldn't stage large files
       - Rapid aggregation (exfiltration prep)
       - Typical staging pattern
       - Volume exceeds normal usage

2. After-Hours Activity
   ├─ User: "Domain\Employee"
   ├─ Time: 2-4 AM
   ├─ Files: 5-10 ZIP files
   ├─ Total: 700 MB
   └─ Red Flags:
       - After-hours (suspicious)
       - Multiple files (staging)
       - Large volume (data theft)
       - Unusual for this user

3. Suspicious Files Included
   ├─ ZIP Contents: Database backups, credentials files, source code
   ├─ Files: DB dumps, password lists, proprietary code
   ├─ User: Non-IT employee
   └─ Red Flags:
       - Access to sensitive data unusual
       - Database backups shouldn't be in Temp
       - Password lists indicate credential theft
       - Source code theft

4. Rapid Deletion Pattern
   ├─ Created: 5 large ZIPs
   ├─ Duration: 1 hour
   ├─ Deleted: Same day (cleanup)
   ├─ Pattern: Create → Exfiltrate → Delete
   └─ Red Flags:
       - Evidence cleanup
       - Hide staging activity
       - Professional attacker behavior
       - Deliberate concealment

5. Network Transfer Correlation
   ├─ Timestamp: ZIPs created 14:00
   ├─ Network: Large upload 14:15-14:45
   ├─ Size: Matches ZIP volume
   └─ Red Flags:
       - Create → Send pattern
       - Immediate exfiltration
       - Perfect correlation
       - Orchestrated attack
```

---

## Analysis & Findings

### What We're Looking For

**Data Staging Indicators:**
```
✅ Location: C:\Temp\ (temp directory)
✅ Format: ZIP files (compression for transfer)
✅ Volume: > 500 MB (suspicious amount)
✅ User: Unusual (non-admin, non-backup)
✅ Timing: Off-hours, rapid creation
✅ Cleanup: Files deleted shortly after
✅ Correlation: Network upload at same time
```

### Why 500 MB Threshold?

```
Normal Activity:
└─ Single files: 50-200 MB
└─ Occasional: 200-400 MB
└─ Rare: 400-500 MB

Suspicious Activity:
└─ Data staging: 500 MB+
└─ Multiple files rapid succession
└─ Total aggregation exceeds normal usage
```

### Findings Interpretation

**GREEN (Benign):**
```
- Documented backup/software work
- Admin users only
- Expected file sizes
- Business hours
- Regular pattern
```

**YELLOW (Suspicious):**
```
- Unusual user creating large ZIPs
- Multiple files in short timeframe
- Off-hours execution
- No documented purpose
- Cleanup activity
```

**RED (Critical):**
```
- Non-IT users accessing sensitive data
- 1+ GB data staging
- Rapid create-delete pattern
- Network upload correlation
- Multiple indicators present
```

---

## Recommendations

**If Benign Findings Detected:**
- Document legitimate staging patterns
- Create baseline for normal activity
- Whitelist known processes
- No action required

**If Suspicious Findings Detected:**
1. **IMMEDIATE INVESTIGATION:**
   - Stop any active file transfers
   - Isolate computer from network
   - Preserve files for analysis
   - Check for malware

2. **DATA PROTECTION:**
   - Determine what files were staged
   - Assess sensitivity
   - Check if exfiltrated
   - Notify data owners

3. **FORENSIC ANALYSIS:**
   - Recover deleted ZIPs (file carving)
   - Analyze ZIP contents
   - Check logs for exfiltration
   - Timeline reconstruction

4. **SCOPE ASSESSMENT:**
   - How long has activity been occurring?
   - How much data was exposed?
   - What systems were accessed?
   - Who else was involved?

---

# SUMMARY TABLE: All Hypotheses

| Hypothesis | Query Focus | Benign Signal | Suspicious Signal | Risk Level |
|-----------|-----------|---------------|-------------------|-----------|
| **Lateral Movement** | PSExec/WMIC from non-admin users | Admin usage documented | Low-priv user using tools | HIGH |
| **Credential Dumping** | LSASS memory access (0x1010) | Security software only | Mimikatz, PowerShell, custom tools | CRITICAL |
| **Data Staging** | 500+ MB ZIPs in C:\Temp | Documented backups | Rapid multi-file staging | CRITICAL |

---

# NEW DETECTION RULES RECOMMENDED

## Detection Rule 1: Lateral Movement Alert

**Rule Name:** Suspicious_PSExec_WMIC_Usage

```spl
index=sysmon EventCode=1 (Image="*psexec.exe" OR Image="*wmic.exe")
| where User!="SYSTEM" AND User!="Administrator" AND User!="NETWORK SERVICE"
| stats count by User, Image, dest_ip
| where count > 1
```

**Alert Threshold:** More than 1 execution
**Severity:** HIGH
**Action:** Investigate immediately

---

## Detection Rule 2: LSASS Memory Dump

**Rule Name:** LSASS_Credential_Dumping_Attempt

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess="0x1010"
| where SourceImage!="*svchost.exe" AND SourceImage!="*antivirus.exe"
| stats count by SourceImage, SourceParentImage
```

**Alert Threshold:** Any suspicious source
**Severity:** CRITICAL
**Action:** Kill process, isolate immediately

---

## Detection Rule 3: Large Data Staging

**Rule Name:** Large_File_Staging_TempFolder

```spl
index=sysmon EventCode=11 TargetFilename="C:\\Temp\\*.zip"
| stats sum(FileSize) as total_size by User, Date
| where total_size > 500000000
```

**Alert Threshold:** Over 500 MB
**Severity:** HIGH
**Action:** Investigate user activity

---

# LESSONS LEARNED & NEXT STEPS

## What This Hunting Exercise Teaches Us

1. **Proactive Detection**
   - Don't wait for alerts
   - Search for attack patterns
   - Test hypotheses regularly

2. **Query Design**
   - Start with known attack tactics
   - Filter for suspicious conditions
   - Aggregate data for patterns

3. **Context Matters**
   - User context (admin vs regular)
   - Timing (business hours vs off-hours)
   - Frequency (single vs multiple)
   - Parent process relationships

4. **Baseline vs Anomaly**
   - Know normal patterns
   - Identify deviations
   - Document exceptions
   - Regular review needed

## Next Steps (Day 18-21)

1. **Refine Queries**
   - Test on actual environment
   - Adjust thresholds
   - Reduce false positives
   - Optimize performance

2. **Create Detection Rules**
   - Implement recommended alerts
   - Test for effectiveness
   - Document baseline
   - Train SOC team

3. **Hunting Campaign**
   - Monthly threat hunts
   - New hypotheses
   - Share findings
   - Improve detection

4. **Documentation**
   - Maintain query library
   - Document findings
   - Create playbooks
   - Train analysts

---

## Conclusion

Threat hunting exercise demonstrates importance of proactive threat detection. Three hypotheses tested (lateral movement, credential dumping, data staging) reveal critical gaps in detection capability. Recommended detection rules will significantly improve security posture. Continuous hunting should become regular practice to stay ahead of advanced threats.

**Status:** Hunting Exercise Complete - Ready for Rule Implementation  
**Next Phase:** Detection Rule Creation (Day 18-21)  
**Recommendation:** Implement all three detection rules immediately

---

**Report Completed:** 2026-06-24  
**Analyst:** Abdulrhman (Levi)  
**Classification:** Internal - SOC Training
