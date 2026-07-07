Custom Detection Rules 
Date: 2026-06-25
Analyst: Abdulrhman (Levi)

Detection Rule 1: Brute Force Login Attempts
Severity: HIGH | MITRE: T1110
Splunk Query:
splindex=main EventCode=4625
| bucket _time span=5m
| stats count as failures by src_ip, user
| where failures > 10
Elastic Query:
event.code: 4625 | stats failures=count() by source.ip, user.name | filter failures > 10
Alert Trigger: >10 failed logins in 5 minutes
Action: Investigate account
Expected: Brute force attack detected

Detection Rule 2: Office App Spawning Suspicious Process
Severity: CRITICAL | MITRE: T1203
Splunk Query:
splindex=sysmon EventCode=1
| search ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE"
| search Image="*cmd.exe" OR Image="*powershell.exe"
Elastic Query:
process.parent.name: (WINWORD.exe OR EXCEL.exe) AND process.name: (cmd.exe OR powershell.exe)
Alert Trigger: Any Office → cmd/PowerShell spawn
Action: Kill process, Isolate immediately
Expected: Malware execution attempt detected

Detection Rule 3: Lateral Movement - PSExec/WMIC
Severity: HIGH | MITRE: T1570
Splunk Query:
splindex=sysmon EventCode=1
| search Image="*psexec.exe" OR Image="*wmic.exe"
| where User!="SYSTEM" AND User!="Administrator"
Elastic Query:
process.name: (psexec.exe OR wmic.exe) AND NOT user.name: (Administrator OR SYSTEM)
Alert Trigger: Non-admin using PSExec/WMIC
Action: Investigate lateral movement
Expected: Unauthorized tool usage detected

Detection Rule 4: Large Data Upload to External Domain
Severity: CRITICAL | MITRE: T1041
Splunk Query:
splindex=proxy dest_domain!=company.com
| where bytes_out > 1000000000
| stats sum(bytes_out) as total by src_ip, dest_domain
| where total > 1000000000
Elastic Query:
destination.domain: * AND NOT destination.domain: company.com 
| stats upload_bytes=sum(network.bytes) by source.ip, destination.domain 
| filter upload_bytes > 1073741824
Alert Trigger: >1 GB upload to external domain
Action: Block connection, Investigate data loss
Expected: Data exfiltration attempt detected

Detection Rule 5: Registry Run Key Modification
Severity: HIGH | MITRE: T1547.008
Splunk Query:
splindex=sysmon EventCode=13
| search TargetObject="*\\CurrentVersion\\Run*"
| where User!="SYSTEM" AND User!="Administrator"
Elastic Query:
event.code: 13 AND registry.path: "*\\CurrentVersion\\Run*" 
AND NOT user.name: (SYSTEM OR Administrator)
Alert Trigger: Non-admin modifying Run keys
Action: Investigate persistence attempt
Expected: Persistence mechanism detected

Rule Deployment Summary
RuleAlert WhenSeverityAction1. Brute Force>10 fails/5minHIGHInvestigate2. Office SpawnAny spawnCRITICALKill + Isolate3. Lateral MovementNon-admin toolHIGHInvestigate4. Data Exfiltration>1 GB externalCRITICALBlock + Investigate5. Registry PersistenceNon-admin modifyHIGHInvestigate

Tuning Recommendations

Brute Force: Increase to 15-20 if too noisy
Office Spawn: Keep strict (high confidence)
Lateral Movement: Whitelist documented admins
Data Exfiltration: Whitelist SaaS (OneDrive, Dropbox)
Registry: Exclude known installers


Performance Baseline
Expected Alert Volume (Weekly):

Brute Force: 2-5 alerts
Office Spawn: 0-1 alerts
Lateral Movement: 1-3 alerts
Data Exfiltration: 0-2 alerts
Registry Persistence: 1-4 alerts

False Positive Rate: 10-30% (tune thresholds)

Implementation Steps

Test: Run queries on lab data
Baseline: Monitor normal activity (1-2 weeks)
Tune: Adjust thresholds based on findings
Deploy: Activate in production
Monitor: Review alerts daily
