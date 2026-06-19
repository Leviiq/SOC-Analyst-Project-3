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

## Practice Exercises (To Complete)

### Exercise 1: Find all failed login attempts in last 24 hours
**Query:**
```spl
index=main EventCode=4625 earliest=-24h
```

### Exercise 2: Identify top 5 users with most failed logins
**Query:**
```spl
index=main EventCode=4625 | stats count by user | sort -count | head 5
```

### Exercise 3: Detect brute force (>10 failed logins from same IP in 5 min)
**Query:**
```spl
index=main EventCode=4625 | stats count as failed_logins by src_ip, user | where failed_logins > 10
```

---

**Status:** Ready for hands-on practice  
**Next Step:** Apply queries to real log data
