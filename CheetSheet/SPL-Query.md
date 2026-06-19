# SPL Cheatsheet - Project 3: SIEM Fundamentals

**Source:** TryHackMe - Splunk: Exploring SPL  
**Date:** 2026-06-19  
**Analyst:** Abdulrhman (Levi)

---

## Core SPL Commands to Master

### 1. Basic Search
```spl
index=main sourcetype=windows_security EventCode=4624
```
**Purpose:** Find successful logins (EventCode 4624)  
**Fields:**
- `index=main` - Search in main index
- `sourcetype=windows_security` - Windows security events only
- `EventCode=4624` - Successful logon events

**Output:** All successful login events

---

### 2. Filtering and Selecting Fields
```spl
index=main EventCode=4625 | fields _time, user, src_ip, ComputerName
```
**Purpose:** Show only failed logins with specific fields  
**Breakdown:**
- `index=main` - Search main index
- `EventCode=4625` - Failed login attempts
- `| fields` - Select specific columns
- Fields displayed: time, user, source IP, computer name

**Output:** Table with 4 columns showing failed login details

---

### 3. Statistics and Aggregation
```spl
index=main EventCode=4625 | stats count by user, src_ip | sort -count
```
**Purpose:** Count failed logins grouped by user and IP  
**Breakdown:**
- `index=main` - Search main index
- `EventCode=4625` - Failed logins
- `| stats count by user, src_ip` - Group by user and IP, count occurrences
- `| sort -count` - Sort descending (highest count first)

**Output:** Table showing which users failed most from which IPs

---

### 4. Timeline Visualization
```spl
index=main user="admin" | timechart count by EventCode
```
**Purpose:** Visualize admin events over time  
**Breakdown:**
- `index=main` - Search main index
- `user="admin"` - Filter for admin user only
- `| timechart count by EventCode` - Show event counts over time by type
- Time intervals shown on X-axis, event codes on separate lines

**Output:** Line chart showing event frequency over time

---

### 5. Subsearches for Correlation
```spl
index=main [search index=main EventCode=4720 | fields user] EventCode=4732
```
**Purpose:** Find users who were created AND added to groups  
**Breakdown:**
- Inner search: `[search index=main EventCode=4720 | fields user]`
  - Finds newly created users (EventCode 4720)
  - Gets their usernames
- Outer search: `index=main ... EventCode=4732`
  - Finds group member additions (EventCode 4732)
  - But ONLY for users from inner search
- Correlation: Links user creation to group membership

**Output:** Events where a newly created user was added to a group

---

## What These Queries Teach Us

| Query | Technique | Use Case |
|-------|-----------|----------|
| Basic Search | Filtering single events | Find specific event types |
| Filtering Fields | Column selection | Reduce data, improve readability |
| Statistics | Aggregation/grouping | Identify patterns and anomalies |
| Timeline | Time-based visualization | Detect trends and timing |
| Subsearch | Correlation | Find related events |

---

## Practice Exercises - TryHackMe Room Solutions

### Task 2: Basic Search

**Q1: All Time events in windowslogs index**
```spl
index=windowslogs
```
**Answer:** [Total event count from room]

---

**Q2: Most frequent SourceIP**
```spl
index=windowslogs
| top SourceIP
```
**Answer:** [SourceIP with highest count]

---

**Q3: Events on 04/15/2022 from 08:05 AM to 08:06 AM**
```spl
index=windowslogs
| timechart span=1m count
```
**Answer:** [Event count in that time window]

---

### Task 3: Search Operators

**Q1: EventID 4624 count**
```spl
index=windowslogs EventID=4624
```
**Answer:** [Total count]

---

**Q2: DestinationIp=172.18.39.6 and DestinationPort=135**
```spl
index=windowslogs DestinationIp=172.18.39.6 DestinationPort=135
```
**Answer:** [Event count]

---

**Q3: Highest SourceIp for Salena.Adam to 172.18.38.5**
```spl
index=windowslogs Hostname=Salena.Adam DestinationIp=172.18.38.5
| stats count by SourceIp
| sort - count
```
**Answer:** [SourceIP with highest count]

---

**Q4: Events matching "cyber*"**
```spl
index=windowslogs cyber*
```
**Answer:** [Total count]

---

**Q5: Lowest priority operator in Splunk**
```spl
index=windowslogs
| search cyber*
```
**Answer:** [Operator name]

---

### Task 4: Filtering Results

**Q1: Highest SourceProcessId**
```spl
index=windowslogs
| fields Domain SourceProcessId TargetProcessId
| stats count by SourceProcessId
| sort - SourceProcessId
```
**Answer:** [Highest SourceProcessId]

---

**Q2: TargetObject ending with "Manager"**
```spl
index=windowslogs
| regex TargetObject="Manager$"
```
**Answer:** [TargetObject value with most results]

---

### Task 5: Structuring Results

**Q1: First AccountName in table**
```spl
index=windowslogs
| table EventID AccountName AccountType
```
**Answer:** [First AccountName]

---

**Q2: First EventID after reverse**
```spl
index=windowslogs
| table EventID AccountName AccountType
| reverse
```
**Answer:** [First EventID after reversing]

---

**Q3: Password given to user A1berto**
```spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
```
**Answer:** [Password value]

---

### Task 6: Transforming Commands

**Q1: Most executed Image**
```spl
index=windowslogs EventID=1
| top Image
```
**Answer:** [Most common Image/executable]

---

**Q2: IP Region distribution**
```spl
index=windowslogs
| iplocation SourceIp
| stats count by Region
```
**Answer:** [Region name]

---

**Q3: Highest RiskScore Image**
```spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
```
**Answer:** [Image with highest RiskScore]

---

## Key Takeaways

1. **Piping (|):** Connects commands for powerful analysis
2. **Stats vs Top:** Stats more flexible, Top shows quick results
3. **Regex:** Powerful pattern matching with anchors ($ = end)
4. **Lookup:** Enriches data with external information
5. **Timeline:** Essential for understanding attack progression

---

**Status:** Ready for real-world Splunk practice  
**Next Step:** Apply queries to actual incident data
