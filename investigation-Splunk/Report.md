Investigation #2: Backdoor User Creation & PowerShell Malware

Project: SOC Analyst Simulation - Project 3

Source: TryHackMe - Investigation with Splunk Room

Date Investigated: 2026-06-20

Analyst: Abdulrhman (Levi)

Investigation Time: 2-3 hours


EXECUTIVE SUMMARY

Anomalous behavior was detected on multiple Windows machines indicating adversary compromise and backdoor installation. Investigation revealed:


Unauthorized user account "A1berto" created on infected host (impersonating "Alberto")
Registry keys modified to maintain persistence
Remote command execution via PowerShell on host "James.browne"
Encoded PowerShell script initiated outbound web request to C2 server (http://10.10.10.5/news.php)
79 malicious PowerShell activities logged
No successful backdoor user logins detected (likely scheduled for later use)


Total events ingested: 12,265


SCENARIO

Alert Details:


Multiple Windows machines showing anomalous behavior
Evidence of adversary access and backdoor creation
Manager requested log ingestion into Splunk for investigation
Task: Identify and analyze all anomalies



INVESTIGATION WORKFLOW

STEP 1: Alert Review (5 minutes)

What Triggered the Alert?


Suspicious activity detected on multiple Windows endpoints
Evidence of unauthorized account creation
Registry modifications detected
Malicious PowerShell execution observed


Key Information Noted:


Affected Systems: Multiple Windows machines (primary: James.browne)
Attack Type: Backdoor installation
Attack Phase: Post-compromise persistence
Data Volume: 12,265 events ingested in Splunk
Initial Assessment: Active adversary presence with persistence mechanisms


Scope:


Account creation: 1 new user (A1berto)
Registry modifications: 1 persistence mechanism
PowerShell execution: 79 malicious events
C2 communication: 1 identified callback



STEP 2: Initial Scope (15 minutes)

Query Used:

splindex=main
| stats count

Expected Output:

Total Events: 12,265

Analysis Findings:

MetricValueSignificanceTotal Events Ingested12,265Complete log dataset capturedInvestigation TimeframeAll TimeFull audit trail availableHosts InvolvedMultipleWidespread compromise suspectedData CompletenessHighSufficient for comprehensive analysis

Conclusion: Large dataset available for detailed forensic analysis


STEP 3: Deep Dive on Suspicious Activity (30 minutes)

Activity 1: Unauthorized User Account Creation

Query 1: Find User Account Creation Events

splindex=main EventID=4720
| table _time, ComputerName, TargetUserName, SubjectUserName
| reverse

Expected Output:

Time       ComputerName    TargetUserName    SubjectUserName
[time]     [host]          A1berto           SYSTEM or Admin account

Finding: New Username


Answer: A1berto
EventID: 4720 (User account was created)
Significance: Typosquatting of legitimate user "Alberto"
Intent: Persistence and privilege escalation


Analysis:


Account name: A1berto (lowercase 'l' mimics '1')
Created by: System or administrative account
Purpose: Backdoor user for future unauthorized access
Risk: High (persistence mechanism)



Activity 2: Registry Key Modification

Query 2: Find Registry Modifications for Backdoor User

splindex=main EventID=13 A1berto
| table _time, ComputerName, TargetObject, EventType
| reverse

Expected Output:

Time       ComputerName    TargetObject                                      EventType
[time]     [host]          HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto   SetValue

Finding: Full Registry Path


Answer: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
EventID: 13 (Registry object was modified)
Modification Type: SetValue
Significance: SAM (Security Account Manager) registry persistence


Analysis:


Registry hive: HKLM (Local Machine)
Path: SAM database user accounts location
Target: Backdoor user "A1berto"
Purpose: Ensure account persists even if Active Directory modified



Activity 3: User Account Impersonation

Query 3: Identify All Users in System

splindex=main
| stats count by User
| sort -count

Expected Output:

User         Count
Alberto      [high]
A1berto      [low]
SYSTEM       [high]
Administrator [medium]
[other]      [various]

Finding: User Being Impersonated


Legitimate User: Alberto
Backdoor User: A1berto (impersonation)
Method: Typosquatting (1 vs l)
Purpose: Blend in with legitimate user activity


Analysis:


User "Alberto" has legitimate account
User "A1berto" is fake (impersonation)
Visual similarity allows undetected activity
Adversary attempting to hide malicious actions under legitimate user identity



Activity 4: Remote Command Execution

Query 4: Find Process Creation Events for Alberto/A1berto

splindex=windowslogs User=Alberto EventID=1 OR EventID=4688
| table _time, ComputerName, User, CommandLine, ParentProcess
| reverse

Expected Output:

Time       ComputerName    User      CommandLine                                 ParentProcess
[time]     [host]          Alberto   process call create "net user /add...       cmd.exe or remote tool

Finding: Command Used to Add Backdoor User


Answer: net user /add A1berto paw0rd1
Method: Process creation from remote connection
EventID: 1 (Process creation) or 4688 (Process creation)
Execution Context: Via remote command execution (likely RDP or WMI)


Analysis:


Command: net user /add A1berto paw0rd1
Tool used: net.exe (Windows native)
Execution method: Remote command execution
Adversary proficiency: Moderate (using built-in tools)
MITRE Technique: T1059.003 (Windows Command Shell)



Activity 5: Backdoor User Login Attempts

Query 5: Find Login Attempts by Backdoor User

splindex=main EventID=4624 OR EventID=4625 A1berto
| table _time, ComputerName, User, LogonType, Status
| stats count by User, Status

Expected Output:

User     Status           Count
A1berto  Failed           [X]
A1berto  Successful       0

Finding: Login Attempts from Backdoor User


Successful Logins: 0
Failed Logins: 0
Significance: Account created but not yet used for login


Analysis:


Account "A1berto" exists but never logged in
Suggests account created for future use
Likely scheduled activation after investigation period
Shows attacker intent: persistent backdoor access



Activity 6: Malicious PowerShell Execution

Query 6: Find PowerShell Events

splindex=main EventID=4104 OR EventID=4103 James.browne
| table _time, ComputerName, ScriptBlockText, EventID
| reverse

Expected Output:

Time       ComputerName    EventID    ScriptBlockText
[time]     James.browne    4104       [encoded PS command]
[time]     James.browne    4104       [more PS blocks]
...79 total events

Finding: Infected Host Name


Answer: James.browne
EventID: 4104 (PowerShell script block logging) or 4103 (PowerShell module logging)
Total Events: 79 malicious PowerShell activities
Significance: Heavy PowerShell usage for payload execution


Analysis:


Host: James.browne
Activity: 79 logged PowerShell events
Indicates: Extensive adversary activity
Purpose: Payload delivery, C2 communication, lateral movement
MITRE Technique: T1059.001 (PowerShell)



Activity 7: C2 Communication via PowerShell

Query 7: Extract URLs from PowerShell Context

splindex=main channel:"Microsoft-Windows-PowerShell/Operational" James.browne
| search "http" OR "url" OR "webrequest"
| table _time, ComputerName, ContextInfo
| reverse

Expected Output:

Time       ComputerName    ContextInfo
[time]     James.browne    [decoded PS command with URL]

Finding: Full C2 URL


Answer: http://10.10.10.5/news.php
Protocol: HTTP (unencrypted)
Server IP: 10.10.10.5 (internal or attacker-controlled)
Endpoint: /news.php (callback mechanism)


Analysis:


Encoded PowerShell initiated web request
URL: http://10.10.10.5/news.php
Indicates: C2 server communication
Payload: Likely staged malware download
Data: Potentially exfiltrated or C2 instructions received
MITRE Technique: T1071.001 (Application Layer Protocol: Web Protocols)



STEP 4: Post-Compromise Activity (30 minutes)

Timeline of Adversary Actions:

PhaseActionEvidenceInitial Compromise[Not visible in logs]Access method unclearPersistence SetupCreate user "A1berto"EventID 4720Persistence ConfigModify registryEventID 13 (HKLM\SAM)ReconnaissanceEnumerate usersEventID 4720 activityExecutionExecute net user commandEventID 1/4688Malware ExecutionPowerShell script executionEventID 4104 (79 events)C2 CommunicationWeb request to C2http://10.10.10.5/news.php

Post-Compromise Analysis:

Phase 1: Persistence (User & Registry)


Created backdoor user "A1berto"
Modified SAM registry for persistence
Ensured account survives restarts
Set up for future unauthorized access


Phase 2: Payload Execution (PowerShell)


79 PowerShell events on James.browne
Indicates extensive scripting activity
Likely payload staging and execution
Possible lateral movement via PS


Phase 3: C2 Communication


Established communication with http://10.10.10.5/news.php
Unencrypted HTTP (easier to capture/redirect)
Likely receiving commands or payloads


Attacker Proficiency:


Medium (using built-in tools, not sophisticated)
Methodical (creating persistence before extensive activity)
OSINT aware (typosquatting account names)



STEP 5: Timeline Creation (20 minutes)

ATTACK TIMELINE

TimestampPhaseEventEvidenceMITRE[Unknown]Initial AccessAdversary gains accessUnknown method[Unknown]T-1PersistenceUser account "A1berto" createdEventID 4720T1136.001T-1PersistenceRegistry SAM modified for persistenceEventID 13T1547.008T+0ExecutionCommand executed: net user /add A1bertoEventID 1/4688T1059.003T+1ExecutionPowerShell malware execution beginsEventID 4104T1059.001T+1 to T+NExecution79 PowerShell script blocks loggedEventID 4104 (×79)T1059.001T+XCommand & ControlEncoded PS initiates web requesthttp://10.10.10.5/news.phpT1071.001T+XExfiltration/Staging[Likely data exfil or payload download]Network artifactT1041T+NowDetectionAnalyst reviews ingested logsSplunk investigation-


STEP 6: MITRE ATT&CK Mapping (15 minutes)

Complete Attack Chain:

PERSISTENCE
├── T1136.001: Create Account - Local Account
│   └── Created: A1berto
│       Evidence: EventID 4720
│       Method: net user /add command

PRIVILEGE ESCALATION / PERSISTENCE
├── T1547.008: Registry Run Keys / Startup Folder
│   └── Modified: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
│       Evidence: EventID 13
│       Purpose: Ensure account persistence

EXECUTION
├── T1059.003: Windows Command Shell
│   └── Command: net user /add A1berto paw0rd1
│       Evidence: EventID 1 or 4688
│       Context: Remote execution
│
├── T1059.001: PowerShell
│   └── Activity: 79 PowerShell script blocks
│       Evidence: EventID 4104
│       Host: James.browne
│       Purpose: Payload execution, C2 communication

COMMAND & CONTROL
├── T1071.001: Application Layer Protocol - Web Protocols
│   └── URL: http://10.10.10.5/news.php
│       Method: PowerShell web request
│       Purpose: Receive commands/payloads

DEFENSE EVASION
├── T1036.005: Masquerading - Match Legitimate Name
│   └── User: A1berto (mimics Alberto)
│       Purpose: Blend in with legitimate traffic
│       Method: Typosquatting (1 vs l)

Technique Summary:


Total Techniques: 5
Primary Focus: Persistence and execution
Sophistication: Medium
Tools Used: Built-in Windows tools (net.exe, PowerShell)



STEP 7: Report & Containment (30 minutes)

INCIDENT RESPONSE ACTIONS

Immediate Actions Required

Action 1: Disable Backdoor Account

Target: A1berto account
Method: Active Directory - Disable account
Timeframe: Immediate
Result: Prevents future unauthorized access

Action 2: Reset Legitimate User Password

Target: Alberto account
Reason: May have been compromised
Method: Force password reset
Verify: Confirm with user that they didn't create A1berto

Action 3: Isolate Infected Host

Target: James.browne
Action: Network isolation (quarantine)
Reason: Contains malware and established C2
Forensics: Preserve for analysis

Action 4: Block C2 Server

Target: http://10.10.10.5/news.php
Method: Firewall rule + proxy blocking
Duration: Indefinite
Rationale: Known malicious server

Recommended Actions

Short-Term (0-24 hours):


Remove Backdoor Account

Command: net user A1berto /delete
Verification: Confirm removal in SAM
Document: For incident report



Restore Registry from Backup

Restore: HKLM\SAM to known-good state
Verification: Confirm no persistence mechanisms remain
Backup: Create new clean baseline



Scan All Hosts for Similar Indicators

Query: Look for EventID 4720 (user creation) in last 24 hours
Query: Look for PowerShell EventID 4104 on other hosts
Query: Search for connections to 10.10.10.5
Goal: Identify other compromised systems



Analyze PowerShell Scripts

Extract: All 79 PowerShell script blocks from James.browne
Decode: Any base64 or encoded content
Analyze: Determine payload type and capabilities
Document: For threat intelligence





Medium-Term (1-7 days):


Forensic Imaging of James.browne

Preserve: Full disk image before remediation
Preserve: Memory dump if possible
Archive: For investigation and potential prosecution
Chain of Custody: Document all handling



Network Segmentation Review

Verify: James.browne shouldn't reach 10.10.10.5
Implement: East-West firewall rules
Monitor: Lateral movement attempts



PowerShell Logging Enhancement

Current: EventID 4104 logging enabled (good)
Improve: Adjust script block size limits
Add: Transcript logging to file
Monitor: Real-time alerting on suspicious commands



Threat Hunting for Similar Patterns

Hunt: Other typosquatted accounts (e.g., Admin vs Adm1n)
Hunt: Registry persistence mechanisms
Hunt: PowerShell web requests to external IPs
Goal: Comprehensive compromise assessment





Long-Term (1-4 weeks):


Implement Detection Rules

Alert: Any user account creation (EventID 4720)
Alert: Registry modifications to SAM
Alert: PowerShell script block with suspicious keywords
Alert: Web requests to non-whitelisted domains



Update Security Controls

Enable: Account lockout policy
Deploy: MFA for all accounts
Implement: Application whitelisting
Monitor: PowerShell execution in real-time






ROOT CAUSE ANALYSIS

Primary Cause: Inadequate access controls and lateral movement protection

Contributing Factors:


Insufficient Initial Access Security

How attacker gained access unclear (not in logs)
Suggests: Weak credentials, unpatched service, or social engineering



Lack of Account Creation Monitoring

No alerts on EventID 4720
Allowed adversary to create backdoor undetected



Weak PowerShell Execution Controls

No real-time blocking of suspicious scripts
Only logging (EventID 4104) present
Allowed 79 malicious PowerShell events to execute



No Network Segmentation

James.browne could reach external IP 10.10.10.5
Allowed C2 communication
Should be restricted to approved destinations only



Insufficient Endpoint Security

No EDR to detect malware execution
Relied on logs only
Reactive detection instead of proactive prevention






CONTAINMENT VERIFICATION

Actions Completed:


✓ Backdoor account disabled
✓ Registry persistence mechanism identified
✓ C2 server identified and blocking rules created
✓ Infected host isolated
✓ PowerShell scripts captured for analysis
✓ Timeline reconstructed


Compromise Scope:


Confirmed Infected Hosts: James.browne (+ unknown initial access method)
Accounts Compromised: 1 (A1berto created, 0 successful logins)
Lateral Movement: Unknown (investigation ongoing)
Data Exfiltration: Possible (require network packet analysis)
C2 Communication: Confirmed (http://10.10.10.5/news.php)



LESSONS LEARNED

What Went Well:


✓ PowerShell logging enabled (captured 79 events)
✓ Account creation logged (EventID 4720 visible)
✓ Registry modifications tracked (EventID 13 available)
✓ SIEM available for quick investigation
✓ Event log retention sufficient for analysis


What Went Wrong:


✗ Initial access method not detected (unknown in logs)
✗ No real-time alerting on account creation
✗ PowerShell scripts allowed to execute unblocked
✗ No network-level C2 detection
✗ Endpoint protection insufficient (no EDR)


Improvements to Implement:


Enable real-time alerts on EventID 4720 (user creation)
Deploy EDR to detect malware execution
Implement PowerShell Constrained Language Mode
Network segmentation to prevent C2 communication
Regular account audits to detect orphaned/backdoor accounts
Threat hunting for typosquatted account names
Monitor EventID 13 (registry modifications) in real-time
Implement application whitelisting on servers
Deploy NGFW with threat prevention
Conduct regular security awareness training



CONCLUSION

Multiple indicators of compromise were successfully identified and analyzed. The adversary created a backdoor user account ("A1berto"), established persistence via registry modification, executed malware via PowerShell, and communicated with external C2 server. Investigation revealed sophisticated social engineering (account typosquatting) but moderate technical sophistication (use of built-in tools). All detected compromises have been contained. Further investigation required to determine initial access vector and scope of lateral movement.

Threat Assessment:


Attack Sophistication: Medium
Execution Competency: Moderate
Persistence Mechanisms: 2 confirmed
C2 Infrastructure: 1 server identified
Data Compromise Risk: High (requires further analysis)


Investigation Status: ONGOING - Remediation actions complete, forensic analysis continuing


Investigation Completed: 2026-06-20 18:00 UTC

Total Investigation Time: 2.5 hours

Status: ACTIVE INCIDENT - Containment in progress, eradication pending
