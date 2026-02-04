# Task-12-Log-Monitoring-Analysis
# Incident Investigation Report: Brute Force Detection
**Case ID:** 2026-LOG-012  
**Status:** Resolved  
**Severity:** Medium

---

## 1. Executive Summary
On **February 4, 2026**, during a routine log audit, an anomaly was detected involving a high volume of failed authentication attempts against the primary Linux SSH gateway and subsequent lateral movement attempts on a Windows workstation.

## 2. Technical Findings

### A. Linux Log Analysis (Auth.log)
Investigation of `/var/log/auth.log` revealed a pattern of unauthorized access attempts.

* **Source IP:** `192.168.1.45`
* **Timeframe:** 04:00 AM - 04:15 AM
* **Pattern:** 450 failed login attempts for the user `admin` and `root` in 15 minutes.
* **Command Used for Discovery:**
    ```bash
    grep "Failed password" /var/log/auth.log | cut -d' ' -f11 | sort | uniq -c
    ```



### B. Windows Event Correlation
The attacker successfully compromised a low-privilege service account and attempted to move to a Windows environment.

* **Event ID 4625 (Failed Logon):** 12 instances recorded within 2 minutes on `WORKSTATION-01`.
* **Event ID 4624 (Successful Logon):** Recorded at 04:22 AM.
* **Account Affected:** `SVC_Backup`



---

## 3. SIEM Visualization (Splunk)
Logs were ingested into Splunk to visualize the attack spike.

**SPL Query for Alerting:**
```spl
index=security sourcetype="linux_secure" "Failed password"
| stats count by src_ip
| where count > 100
