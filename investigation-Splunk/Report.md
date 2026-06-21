# Investigation #2: Backdoor User & PowerShell Malware

**Source:** TryHackMe - Investigation with Splunk  
**Date:** 2026-06-20  
**Analyst:** Abdulrhman (Levi)

---

## Executive Summary

Anomalous behavior detected on Windows machines. Adversary created backdoor user "A1berto" (impersonating "Alberto"), modified registry for persistence, executed 79 PowerShell commands on host "James.browne", and established C2 communication to http://10.10.10.5/news.php. Total events: 12,265. No successful backdoor logins detected.

---

## Investigation Steps

### Step 1: Alert Review
- Multiple Windows machines compromised
- Backdoor user account creation detected
- Registry modifications found
- Malicious PowerShell execution observed

### Step 2: Initial Scope

**Query:**
```spl
index=main | stats count
```

**Result:** 12,265 events ingested

### Step 3: Deep Dive Analysis

**Q1: How many events ingested?**
```spl
index=main
```
**Answer:** 12,265

**Q2: Backdoor username?**
```spl
index=main EventID=4720
```
**Answer:** A1berto

**Q3: Registry path modified?**
```spl
index=main EventID=13 A1berto
```
**Answer:** HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto

**Q4: User being impersonated?**
```spl
index=main | stats count by User
```
**Answer:** Alberto (legitimate user, A1berto is fake)

**Q5: Command used to add backdoor user?**
```spl
index=windowslogs Alberto EventID=1 OR EventID=4688
```
**Answer:** net user /add A1berto paw0rd1

**Q6: Backdoor user login attempts?**
```spl
index=main EventID=4624 OR EventID=4625 A1berto
```
**Answer:** 0 (account created but never logged in)

**Q7: Infected host with PowerShell activity?**
```spl
index=main EventID=4104 OR EventID=4103
```
**Answer:** James.browne

**Q8: PowerShell events logged?**
```spl
index=main EventID=4104 James.browne
```
**Answer:** 79 events

**Q9: C2 URL from PowerShell?**
```spl
index=main channel:"Microsoft-Windows-PowerShell/Operational" James.browne
```
**Answer:** http://10.10.10.5/news.php

### Step 4: Timeline

| Time | Event | Evidence |
|------|-------|----------|
| T-1 | User created | A1berto (EventID 4720) |
| T-1 | Registry modified | HKLM\SAM path (EventID 13) |
| T+0 | Command executed | net user /add A1berto |
| T+1 | PowerShell execution | 79 script blocks (EventID 4104) |
| T+X | C2 communication | http://10.10.10.5/news.php |

### Step 5: MITRE ATT&CK Mapping

- **T1136.001** — Create Account (A1berto created)
- **T1547.008** — Registry Run Keys (SAM persistence)
- **T1059.003** — Windows Command Shell (net user command)
- **T1059.001** — PowerShell (79 script blocks)
- **T1071.001** — Web Protocols (C2 communication)
- **T1036.005** — Masquerading (A1berto mimics Alberto)

### Step 6: Containment Actions

**Immediate:**
- Disable A1berto account
- Reset Alberto password
- Isolate James.browne
- Block C2 IP 10.10.10.5

**Short-term:**
- Remove backdoor account
- Restore registry from backup
- Hunt for similar patterns
- Analyze PowerShell scripts

**Long-term:**
- Implement account creation alerts
- Deploy EDR
- Enable PowerShell Constrained Language Mode
- Network segmentation

### Step 7: Root Cause

**Primary:** Inadequate access controls

**Contributing:**
- Initial access method unclear
- No alerts on user creation
- PowerShell allowed to execute unblocked
- No network segmentation (C2 communication allowed)

---

## Key Findings

| Finding | Value |
|---------|-------|
| Total Events | 12,265 |
| Backdoor Username | A1berto |
| Impersonated User | Alberto |
| Infected Host | James.browne |
| PowerShell Events | 79 |
| C2 URL | http://10.10.10.5/news.php |
| Backdoor Logins | 0 (not used yet) |
| Techniques Used | 6 MITRE techniques |

---

## Recommendations

1. Create real-time alerts for user account creation (EventID 4720)
2. Implement PowerShell script block logging and alerting
3. Network segmentation to prevent C2 communication
4. Deploy endpoint detection and response (EDR)
5. Regular account audits for backdoor detection
6. Hunt for typosquatted account names
7. Monitor registry modifications (EventID 13)
8. Application whitelisting on servers

---

**Status:** Contained - Backdoor account disabled, C2 blocked  
**Investigation Time:** 2.5 hours  
**Next Steps:** Forensic analysis ongoing
