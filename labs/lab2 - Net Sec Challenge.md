# TryHackMe Net Sec Challenge - Complete Walkthrough

*A comprehensive guide to solving the Net Sec Challenge*

---

## Table of Contents

- [Introduction](#introduction)
- [Tools We'll Be Using](#tools-well-be-using)
- [Challenge Walkthrough](#challenge-walkthrough)
- [Key Takeaways](#key-takeaways)
- [Additional Resources](#additional-resources)

## Introduction

Welcome to my walkthrough of the TryHackMe Net Sec Challenge! This medium-difficulty room is designed to reinforce the network security concepts and tools covered in TryHackMe's Network Security module. With an estimated completion time of 60 minutes, this challenge provides excellent hands-on experience with essential penetration testing tools.

**Room Details:**
- **Difficulty:** Medium
- **Duration:** ~60 minutes
- **Focus:** Network reconnaissance, service enumeration, and credential attacks
- **Room Link:** [Net Sec Challenge](https://tryhackme.com/room/netsecchallenge)

## Tools We'll Be Using

### Nmap (Network Mapper)

An indispensable open-source tool for network discovery and security auditing. Key parameters for this challenge:

- `-sC`: Default script scan
- `-sV`: Version detection
- `-sN`: Null scan (stealth)
- `-p-`: Scan all 65,535 ports
- `-T4`: Aggressive timing

### FTP (File Transfer Protocol)
A standard protocol for transferring files between client and server over a network.

### Telnet
A client/server protocol providing access to virtual terminals of remote systems.

### Hydra (THC Hydra)
A parallelized network login cracker used for brute-force attacks against various services.

---

## Challenge Walkthrough

### Task 1: Initial Reconnaissance

Let's start with a basic Nmap scan to identify open services on our target.

```bash
nmap <target_IP>
```

This scans the 1,000 most common TCP ports by default.

### Task 2: Detailed Port Analysis

**Question:** What is the highest port number being open less than 10,000?

Running our initial scan reveals several open ports. The highest port under 10,000 is:

> **Answer:** 8080

---

**Question:** There is an open port outside the common 1,000 ports, it is above 10,000. What is it?

For this, we need to scan all ports:

```bash
nmap -p- <target_IP> -T4
```

> **Answer:** 10021

---

**Question:** How many TCP ports are open?

Analyzing our comprehensive port scan results:

> **Answer:** 6

### Task 3: Service Banner Analysis

**Question:** What is the flag hidden in the HTTP server header?

Let's perform a detailed scan on port 80:

```bash
nmap -sV -sC -p80 <target_IP> -T4
```

This reveals the HTTP server header containing our flag.

> **Answer:** THM{web_server_25352}

---

**Question:** What is the flag hidden in the SSH server header?

We can use Telnet to connect to the SSH service and examine the banner:

```bash
telnet <target_IP> 22
```

> **Answer:** THM{946219583339}

### Task 4: FTP Service Investigation

**Question:** We have an FTP server listening on a nonstandard port. What is the version of the FTP server?

From our port scan, we identified FTP running on port 10021. Let's get version information:

```bash
nmap -sV -sC -p10021 <target_IP> -T4
```

> **Answer:** vsftpd 3.0.5

### Task 5: Credential Brute-forcing

**Question:** We learned two usernames using social engineering: 'eddie' and 'quinn'. What is the flag hidden in one of these two account files and accessible via FTP?

First, create a username file:

```bash
nano usernames.txt
```

Add the usernames:
```
eddie
quinn
```

Now use Hydra to brute-force FTP credentials:

```bash
hydra -t 8 -vV -L usernames.txt -P /usr/share/wordlists/rockyou.txt ftp://<target_IP>:10021
```

Hydra successfully identifies credentials for both users. After connecting via FTP and exploring both accounts, we find the flag in quinn's directory.

> **Answer:** THM{321452667098}

### Task 6: Stealth Scanning Challenge

**Question:** Browsing to http://target_IP:8080 displays a small challenge that will give you a flag once you solve it. What is the flag?

The web challenge on port 8080 requires performing a stealth scan to avoid detection by the IDS (Intrusion Detection System). We need to use a null scan:

```bash
nmap -sN <target_IP>
```

Remember to reset the packet count on the web interface before running the scan.

> **Answer:** THM{f7443f99}

---

## Key Takeaways

This challenge effectively demonstrates several crucial network security concepts:

1. **Comprehensive Port Scanning**: Always scan beyond the common 1,000 ports to discover services on non-standard ports.

2. **Service Enumeration**: Version detection and script scanning provide valuable intelligence about target services.

3. **Banner Grabbing**: Service banners often contain useful information, including flags in CTF scenarios.

4. **Credential Attacks**: Hydra's parallel processing makes it effective for brute-force attacks against network services.

5. **Stealth Techniques**: Different scan types (like null scans) can help evade detection systems.

## Conclusion

The Net Sec Challenge successfully reinforces fundamental network security skills while providing practical experience with industry-standard tools. These techniques form the foundation of professional penetration testing and security assessment methodologies.

Whether you're preparing for certifications like CEH or OSCP, or simply strengthening your cybersecurity skillset, challenges like this provide invaluable hands-on learning opportunities.

---

## Additional Resources

- [TryHackMe Network Security Module](https://tryhackme.com/module/network-security)
- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Hydra Usage Guide](https://tools.kali.org/password-attacks/hydra)

---

> **⚠️ Ethical Hacking Notice**
> 
> Remember to always practice ethical hacking on systems you own or have explicit permission to test!

**Found this walkthrough helpful? ⭐ Star this repository and follow for more cybersecurity content!**
