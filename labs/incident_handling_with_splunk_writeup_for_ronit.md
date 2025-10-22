# Incident Handling with Splunk — Lab Writeup

**Author:** Ronit
**Lab:** TryHackMe — Incident Handling with Splunk
**Purpose:** Detailed lab report suitable as proof-of-work for resume, GitHub repo README, and LinkedIn post. Contains the investigation narrative, findings mapped to the Cyber Kill Chain, Splunk queries used, artifacts (IPs, hashes, domains), recommended remediation, and ready-to-post text for GitHub and LinkedIn.

---

## Executive Summary

During the "Incident Handling with Splunk" lab, I acted as a SOC Analyst investigating a targeted web server compromise at the fictional Wayne Enterprise. The attacker successfully defaced the website `imreallynotbatman.com`. Using Splunk and external threat-intel tools, I traced the attack from reconnaissance through action-on-objective and mapped each activity to the seven phases of the Cyber Kill Chain. Key artifacts (IPs, domain names, file hashes) were identified and analyzed. This writeup documents the approach, queries, evidence, timeline, and remediation recommendations — and is formatted for inclusion in a professional portfolio.

---

## Lab Objective

1. Investigate a webserver compromise and identify how the attacker breached the host.
2. Produce a timeline of attacker activity mapped to the Cyber Kill Chain.
3. Extract Indicators of Compromise (IoCs) such as IP addresses, domains, file names and hashes.
4. Demonstrate the use of Splunk to pivot on logs (webserver, Sysmon, authentication logs) to reconstruct the attack.

---

## Environment & Data Sources

* Target webserver: `imreallynotbatman.com` (Wayne Enterprise)
* Splunk inputs used:
  * Web server logs (access.log, error.log)
  * Windows Sysmon logs (file creation, process creation)
  * Authentication logs
  * Network logs (where available)
* External intel sources used for pivoting: Passive DNS, VirusTotal, shodan-style lookups, OSINT on domains/emails.

---

## Methodology

1. **Triage & Scope:** Identify the compromised assets and determine the primary logs and sources available in Splunk.
2. **Initial Indicators:** Search for defacement-related artifacts (suspicious file writes, changed web root content, HTTP PUT/POST to upload pages/executables).
3. **Pivoting:** Use discovered IPs and file names to pivot across logs (authentication attempts, Sysmon file creation, process execs).
4. **Kill Chain Mapping:** Assign each observed activity to a Cyber Kill Chain phase.
5. **Threat Intel Enrichment:** Query public platforms (VT, passive DNS, whois) with IPs, domains, and file hashes to attribute infrastructure and find related artifacts.
6. **Reporting & Remediation:** Document findings, craft remediation steps and artifacts for containment and eradication.

---

## Splunk Queries (Representative)

> **Note:** Adjust sourcetypes/index names to your environment. These queries are example templates you can paste into Splunk.

### 1) Find web scans and suspicious user agents

```
index=web sourcetype=access_combined
| stats count by clientip, useragent, uri_path
| where match(useragent, "(?i)acunetix|nikto|sqlmap|nessus")
| sort -count
```

### 2) Detect brute-force authentication attempts (by IP)

```
index=auth sourcetype=linux_secure OR sourcetype=wineventlog:security
| stats count AS attempts, earliest(_time) as first, latest(_time) as last by src_ip, user
| where attempts > 20
| sort - attempts
```

### 3) Identify successful login (or privilege escalation) from attacker IP

```
index=auth action=success src_ip=40.80.148.42 OR src_ip=23.22.63.114
| table _time src_ip user action host
```

### 4) Find file uploads or new file creation in webroot (using Sysmon)

```
index=sysmon EventCode=11 OR EventCode=1
| search Image="*\3791.exe" OR TargetFilename="*3791.exe*"
| table _time ComputerName User Image CommandLine TargetFilename Hashes
```

### 5) Extract defacement file and HTTP PUT/POST evidence

```
index=web sourcetype=access_combined (method=POST OR method=PUT) uri_path=* OR uri_query=*
| rex field=uri_path "(?<filename>[^/]+\.(php|html|asp|aspx|exe|scr))"
| stats count by clientip, method, filename, status
| where filename="index.html" OR filename="imreallynotbatman.html" OR filename="3791.exe"
```

---

## Findings — Mapped to the Cyber Kill Chain

### 1) Reconnaissance
**Findings:**
* IP `40.80.148.42` observed scanning the webserver and requesting many application endpoints. Splunk user-agent indicators matched a known web scanner.
* Attacker used the web-scanner `Acunetix` (identified via user-agent strings and request patterns).

**Evidence:** Web server logs showing high-volume probing and characteristic Acunetix user-agent strings.

---

### 2) Weaponization & Delivery
**Findings:**
* Domain observed: `prankglassinebracket.jumpingcrab.com` linked to attacker infrastructure.
* Secondary artifact observed: `MirandaTateScreensaver.scr.exe` (identified through threat intel and associated MD5 hash).

**Evidence:** Passive DNS and threat-intel lookups associating domain and file with the attacker IP `23.22.63.114`.

---

### 3) Exploitation
**Findings:**
* Brute-force login attempts were observed from `23.22.63.114` — 142 unique attempts recorded.
* One attempt succeeded, allowing the attacker to gain valid credentials and interact with the web host.
* The IP `40.80.148.42` was the one used to perform scanning and was associated with exploitation activity.

**Evidence:** Authentication logs (index=auth) showing repeated failed attempts followed by a successful authentication entry.

---

### 4) Installation
**Findings:**
* Malicious executable `3791.exe` was uploaded to the webserver (file creation events observed in Sysmon logs).
* MD5 of `3791.exe` captured from the logs for further analysis.

**Evidence:** Sysmon EventCode=11 (file create) / EventCode=1 (process create) entries showing file name, path and hash.

---

### 5) Command & Control (C2) / Action on Objective
**Findings:**
* After getting access and installing the executable, attacker changed website content — website defacement observed.
* File used to deface the site was identified in webserver content change logs.

**Evidence:** Webserver content served different HTML (defacement page) with filenames and timestamps that map to the timeframe of the successful login and file upload.

---

### 6) Recon (post-compromise) and Lateral Steps
**Findings:**
* Additional outbound connections and DNS queries to masquerading domains were observed.
* Email address `Lillian.rose@po1s0n1vy.com` was surfaced via threat-intel tied to the attacker IPs.

**Evidence:** Passive DNS and OSINT linkage; network logs showing DNS queries to attacker-controlled domains.

---

## Key Artifacts / Indicators of Compromise (IoCs)

* **Attacker scanning IP:** `40.80.148.42`
* **Brute-force source IP:** `23.22.63.114` (142 attempts, 1 successful)
* **Uploaded malicious filename:** `3791.exe`
* **Defacement filename:** (identified in web logs — e.g., `index.html` replaced with defacement page)
* **Malware name (threat intel):** `MirandaTateScreensaver.scr.exe`
* **Malware MD5:** `c99131e0169171935c5ac32615ed6261`
* **Attack domain:** `prankglassinebracket.jumpingcrab.com`
* **Email linked to adversary:** `Lillian.rose@po1s0n1vy.com`

> Tip: Add these IoCs to detection rules, blocklists, and SIEM correlation logic. Submit files/hashes to your malware analysis pipeline or to VirusTotal for deeper analysis.

---

## Timeline (Concise)

1. **Reconnaissance:** `40.80.148.42` scanned multiple endpoints (time T1).
2. **Brute-force attempts:** `23.22.63.114` performed 142 attempts over T2–T3; succeeded at T3.
3. **Upload / Installation:** `3791.exe` uploaded and executed at T4 (Sysmon EventCode entries recorded).
4. **Action on Objective:** Website defaced at T5.
5. **Post-compromise activity:** DNS queries and outbound communications to `prankglassinebracket.jumpingcrab.com` at T6.

---

## Remediation & Hardening Recommendations

1. **Containment:**
   * Isolate the compromised web host from the network immediately.
   * Revoke any credentials that were used by the attacker and reset service account passwords.

2. **Eradication:**
   * Remove malicious files (e.g., `3791.exe`) and any webroot modifications. Rebuild from known-good backups if possible.
   * Re-image the server if persistence mechanisms are suspected.

3. **Recovery:**
   * Restore website from clean backups after verification.
   * Harden authentication (disable password auth where possible, enforce MFA for admin accounts).

4. **Detection Improvements:**
   * Create Splunk alerts for: high-rate web scanning patterns, unusual user-agents (Acunetix), large numbers of failed authentication attempts from single IPs, unexpected file-creation events in webroot.
   * Add IoCs (IPs, domains, hashes) to firewall/IDS/IPS blocklists.

5. **Prevention:**
   * Implement WAF rules to block web scanners and known malicious user agents.
   * Enforce rate limiting and account lockout policies to prevent brute-force attacks.
   * Keep web application and server software patched.

6. **Threat Intelligence & Follow-up:**
   * Submit `3791.exe` and `MirandaTateScreensaver.scr.exe` to malware analysis tools (e.g., VirusTotal, in-house sandbox).
   * Share IoCs with relevant threat-sharing groups or your internal Intel team.

---

## Appendices

### A — Splunk Saved Searches / Alerts (Examples)

**High-rate web scanner detection (saved search):**
```
index=web sourcetype=access_combined
| stats count BY clientip, useragent
| where count > 500 AND match(useragent, "(?i)acunetix|nikto|sqlmap|nessus")
```

**Brute-force detection (alert):**
```
index=auth
| stats count BY src_ip, user
| where count > 50
```

### B — Evidence Collection Checklist

* Export relevant Splunk search results as CSV (include timestamps).
* Download the suspicious file(s) from host if available and submit to sandbox/VT.
* Preserve full disk images and memory snapshots if legal/policy allows.
* Collect process lists, autoruns, and scheduled tasks from the compromised host.

### C — Resume Bullet (Ready-made)

```
Investigated and remediated a simulated webserver compromise in the "Incident Handling with Splunk" lab: performed log triage across web, authentication and Sysmon logs; mapped attacker activity to the Cyber Kill Chain; extracted IoCs (IPs: 40.80.148.42, 23.22.63.114; hashes: c99131e0169171935c5ac32615ed6261); created Splunk detection queries and remediation recommendations.```

---

## GitHub README (Ready-to-use)

> Place this `README.md` at the root of a dedicated repo `incident-handling-splunk-ronit`.

```
# Incident Handling with Splunk — Lab Report (Ronit)

This repository contains a full writeup of the TryHackMe "Incident Handling with Splunk" lab completed by Ronit. It includes details of the investigation, Splunk queries used, IoCs, remediation steps and a concise timeline.

## Contents
- `writeup.md` — Lab report and findings.
- `splunk-queries.md` — Ready-to-run Splunk queries and saved-search examples.
- `iocs.csv` — Indicators of Compromise (IPs, domains, hashes).
- `screenshots/` — (Optional) Screenshots exported from Splunk for evidence.

## How to use
1. Review `writeup.md` for the investigation narrative.
2. Import `splunk-queries.md` into your Splunk instance and tailor sourcetypes/indexes.
3. Add the IoCs from `iocs.csv` into your blocklists and detection rules.

## Contact
Ronit — add contact/email here.
```

---

## LinkedIn Post (Short & Professional) — Ready to Copy

> *Suggested post copy for sharing the lab completion on LinkedIn.*

```
Excited to share that I completed the "Incident Handling with Splunk" lab on TryHackMe. As a SOC Analyst I investigated a simulated webserver compromise, mapped the attacker actions to the Cyber Kill Chain, extracted IoCs (IP addresses, domains, file hashes), and built Splunk detection queries to detect and prevent similar attacks. Details and a full writeup are available on my GitHub: <REPO_LINK>

If you're interested in Splunk-based investigations or SOC playbooks, let's connect!
```

---

## How I suggest you publish this (step-by-step)

1. **Create GitHub repo**
   * Repo name: `incident-handling-splunk-ronit`.
   * Add files: `writeup.md` (this full writeup), `splunk-queries.md`, `iocs.csv`, `README.md`, and any screenshots.
   * Commit message example: `feat: add Incident Handling with Splunk lab writeup and IoCs`

2. **Push to GitHub**

```bash
git init
git add .
git commit -m "feat: add Incident Handling with Splunk lab writeup and IoCs"
git branch -M main
git remote add origin https://github.com/<your-username>/incident-handling-splunk-ronit.git
git push -u origin main
```

3. **Share on LinkedIn**
   * Copy the LinkedIn post content above and paste into a new LinkedIn post. Attach the GitHub repo link and optionally a screenshot of your Splunk timeline.

4. **Optional — Gist & Resume**
   * Create a GitHub Gist for `splunk-queries.md` to make the queries easily shareable.
   * Add the resume bullet in your CV under the relevant job/project section and push an updated resume to your GitHub repo.

---

## Legal & Ethics Note

This writeup documents a simulated lab environment. Do not use the techniques or IoCs to attack systems that you do not own or have explicit permission to test. Always follow your organization's policies and applicable laws when performing investigations or active response.

---

## Next Steps (If you'd like me to do more)

* I can convert these Splunk queries into saved-search JSON you can import into Splunk.
* I can build a `splunk-queries.md` file with copy-paste queries and alert configurations.
* I can generate a polished `README.md` and `iocs.csv` files for direct upload to GitHub.





