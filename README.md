# 🛡️ Purple Team SSH Brute Force Detection Lab

> **Simulated MITRE ATT&CK T1110 (Brute Force), detected in Splunk, and mitigated with Fail2ban**

**Author:** Ugal Sharma  
**GitHub:** [@Ugal-57](https://github.com/Ugal-57)  
**Framework:** MITRE ATT&CK v14  

---

## 📌 Project Summary

A fully isolated purple team home lab where I acted as both **attacker (red team)** and **defender (blue team)**. Generated real SSH brute force traffic from Kali Linux, ingested logs into Splunk via Universal Forwarder, built SPL detection queries, created a live monitoring dashboard, configured automated alerts, and hardened the target host with Fail2ban.

This project demonstrates hands-on skills in SIEM engineering, threat detection, log analysis, and host hardening — mapped to the MITRE ATT&CK framework.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ISOLATED LAB NETWORK                  │
│                   192.168.56.0/24                        │
│                                                          │
│  ┌─────────────┐          ┌─────────────────────────┐   │
│  │  Kali Linux  │ ──SSH──▶ │    Ubuntu 22.04 Target  │   │
│  │ 192.168.56.1 │  attack  │    192.168.56.106        │   │
│  │ 192.168.56.108│         │    OpenSSH + Fail2ban    │   │
│  │  RED TEAM   │          │    Splunk UF              │   │
│  └─────────────┘          └────────────┬────────────┘   │
│                                        │                  │
│                                        │ logs via         │
│                                        │ TCP 9997         │
│                                        ▼                  │
│                           ┌────────────────────────┐     │
│                           │   Splunk Enterprise     │     │
│                           │   192.168.56.105        │     │
│                           │   SIEM + Dashboard      │     │
│                           │   + Alerts              │     │
│                           └────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|---|---|
| Kali Linux | Attacker machine — Hydra brute force |
| Ubuntu 22.04 LTS | Target machine — OpenSSH server |
| Splunk Enterprise | SIEM — log indexing, detection, dashboards |
| Splunk Universal Forwarder | Ships auth.log to Splunk indexer |
| Hydra | SSH brute force tool |
| Fail2ban | Host-based intrusion prevention |
| VirtualBox | Hypervisor — isolated Host-Only network |

---

## 📋 MITRE ATT&CK Mapping

| Technique | ID | What I Did | Detection | Mitigation |
|---|---|---|---|---|
| Brute Force | T1110 | Hydra dictionary attack via SSH | Splunk auth.log monitoring | Fail2ban IP ban |
| Password Guessing | T1110.001 | Wordlist attack against labuser | Failed password threshold alert | Strong password policy |
| Password Spraying | T1110.003 | Low-and-slow SSH loop with delays | Baseline anomaly detection | Account lockout policy |
| User Account Authentication | DS0002 | Monitored auth.log events | SPL detection query | N/A — detection source |

---

## 🔧 Lab Setup

### Network Configuration
- **Hypervisor:** VirtualBox with Host-Only Adapter (`192.168.56.0/24`)
- **All VMs isolated** — no internet exposure during testing
- **Static IPs** configured via NetworkManager (nmcli)

### VM Specifications

| VM | OS | RAM | Role |
|---|---|---|---|
| Kali Linux | Kali Rolling | 2GB | Attacker |
| Ubuntu Target | Ubuntu 22.04 LTS | 2GB | SSH Target |
| Splunk SIEM | Ubuntu 22.04 LTS | 4GB | Log Indexer |

---

## 📡 Splunk Pipeline Configuration

### inputs.conf (Universal Forwarder on Ubuntu Target)
```ini
[monitor:///var/log/auth.log]
disabled = false
index = linux_logs
sourcetype = ssh_auth
```

### outputs.conf (Universal Forwarder on Ubuntu Target)
```ini
[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = 192.168.56.105:9997
```

---

## ⚔️ Attack Simulation

### Phase 1 — Burst Attack (T1110.001)
```bash
# Hydra dictionary attack from Kali
hydra -l labuser -P wordlist.txt 192.168.56.106 ssh -t 4 -V
```

### Phase 2 — Low and Slow Attack (T1110.003)
```bash
# Spread attempts over time to evade simple threshold detection
for i in $(seq 1 20); do
  ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=2 \
      wronguser@192.168.56.106 2>/dev/null
  sleep 15
done
```

### Evidence in auth.log
```
Mar 28 17:35:21 ubuntu-vm sshd[9096]: Failed password for labuser from 192.168.56.108 port 41328 ssh2
Mar 28 17:35:22 ubuntu-vm sshd[9096]: Failed password for labuser from 192.168.56.108 port 41329 ssh2
Mar 28 17:35:23 ubuntu-vm sshd[9096]: Failed password for invalid user wronguser from 192.168.56.1 port 41330 ssh2
```

---

## 🔍 SPL Detection Queries

### Core Detection — SSH Brute Force
```spl
index=linux_logs sourcetype=ssh_auth ("Failed password" OR "authentication failure")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (invalid user )?(?<user>\S+)"
| bin _time span=1m
| stats count as failures by _time src_ip user
| where failures > 3
| eval severity = if(failures > 50, "CRITICAL",
    if(failures > 25, "HIGH", "MEDIUM"))
| sort -failures
```

### Baseline Normal Traffic
```spl
index=linux_logs sourcetype=ssh_auth
| eval login_type = case(
    match(_raw, "Accepted password"), "SUCCESS",
    match(_raw, "Failed password"), "FAILURE",
    match(_raw, "Invalid user"), "INVALID_USER",
    true(), "OTHER")
| timechart span=1m count by login_type
```

### Top Attacking IPs
```spl
index=linux_logs sourcetype=ssh_auth "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failures by src_ip
| sort -failures
```

---

## 📊 Dashboard Panels

| Panel | Visualization | SPL Query Focus |
|---|---|---|
| Failed Logins Over Time | Line Chart | timechart of failed passwords |
| Top Attacking IPs | Bar Chart | top 10 source IPs by count |
| Targeted Usernames | Statistics Table | top 10 targeted usernames |
| Brute Force Incidents | Statistics Table | threshold breaches with severity |

---

## 🚨 Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | SSH_BruteForce_Detected |
| Schedule | Every 5 minutes (`*/5 * * * *`) |
| Time Range | Last 15 minutes |
| Trigger | Number of results > 0 |
| Severity | High |
| Throttle | 60 seconds |
| Action | Add to Triggered Alerts |

---

## 🛡️ Fail2ban Hardening

### SSH Jail Configuration
```ini
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
findtime = 60
bantime = 3600
```

### Before vs After Results

| Metric | Before Fail2ban | After Fail2ban |
|---|---|---|
| Attack duration | Unlimited | Blocked after 5 attempts |
| Failed attempts | 100s per minute | Max 5 then banned |
| Attacker IP status | Active | Banned for 1 hour |
| Splunk dashboard | Continuous spike | Sharp drop after ban |

### Verify Banned IPs
```bash
sudo fail2ban-client status sshd
```

---

## 📸 Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/Dashboard_1.png` | Splunk dashboard overview — panel 1 and 2 |
| `screenshots/Dashboard_2.png` | Splunk dashboard overview — panel 3 and 4 |
| `screenshots/Alert_triggered.png` | SSH_BruteForce_Detected alert firing in Splunk |
| `screenshots/auth_log_entries.png` | Raw failed password entries in auth.log |
| `screenshots/baselined_normal_traffic.png` | Baseline normal SSH traffic SPL query results |
| `screenshots/fail_to_ban.png` | Fail2ban actively banning attacking IP |
| `screenshots/fail_to_ban_log.png` | Fail2ban log showing ban events in real time |
| `screenshots/hydra_output.png` | Hydra brute force attack running from Kali |
| `screenshots/hydra_output_after_ban.png` | Hydra output after Fail2ban blocks the IP |
| `screenshots/linux_logs.png` | Splunk linux_logs index receiving data |
| `screenshots/top_attacking_IPs.png` | SPL query showing top attacking source IPs |
---

## 📁 Repository Structure

```
purple-team-ssh-lab/
├── README.md         
└── screenshots/       
    ├── dashboard_overview.png
    ├── alert_triggered.png
    ├── fail2ban_ban.png
    ├── auth_log_entries.png
    └── hydra_output.png
```

## 🎓 What I Learned

**Red Team Skills:**
- Simulated MITRE ATT&CK T1110 and T1110.003 using Hydra against an authorized lab target
- Understood how burst vs low-and-slow attacks differ in detection difficulty
- Learned how attackers target specific usernames and vary timing to evade detection

**Blue Team Skills:**
- Deployed Splunk Enterprise and configured end-to-end log ingestion pipeline
- Wrote SPL queries to extract threat indicators — source IPs, usernames, timestamps
- Built a 4-panel real-time monitoring dashboard for SSH threat visibility
- Configured automated alerts with threshold-based triggering and throttling

**Detection Engineering:**
- Learned the difference between burst and low-and-slow attacks and how threshold tuning affects false positive and negative rates
- Built a baseline of normal SSH traffic to identify anomalies
- Mapped all detections to MITRE ATT&CK framework — a standard SOC practice

**Host Hardening:**
- Deployed Fail2ban with custom SSH jail and demonstrated measurable before/after impact
- Configured OpenSSH with verbose logging, disabled root login, and limited auth attempts

---

## ⚠️ Legal Notice

**This lab was conducted entirely on systems I own in an isolated private network. All attack simulation was performed only against authorized targets. Never attempt to replicate these techniques against systems you do not own or have explicit written permission to test.**

---

