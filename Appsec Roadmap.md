# 12-Month Application Security Engineer Roadmap (2025-2026)

## Core Philosophy & Dependencies

**Month 1-3**: Foundation (web fundamentals, basic vulnerabilities, manual testing) **Month 4-6**: Depth (source code review, authentication, business logic) **Month 7-9**: Breadth (API security, cloud, automation, CI/CD integration) **Month 10-12**: Professional Readiness (advanced exploitation, reporting, portfolio)

**Why this sequence?** You cannot review code without understanding what the code _does_. You cannot test APIs without understanding HTTP. You cannot integrate security into CI/CD without knowing what vulnerabilities to detect. Each month builds concrete capabilities on previous foundations.

---

## MONTH 1: Web Application Fundamentals & HTTP Mastery

**Why Now**: AppSec requires understanding how web apps work before breaking them. HTTP is the foundation of all web security.

| Week                                                 | Daily Tasks (90 min/day)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Resources                                                                                                       | Completion Criteria                                                                                     | Why This Week                                    |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **Week 1: HTTP Protocol Deep Dive**                  | **Day 1**: Install Burp Suite Community. Complete PortSwigger's "Getting Started" tutorial. Capture traffic from 3 websites. - [[Burp Suite Setup & HTTP Traffic Capture]]<br>**Day 2**: PortSwigger Academy - "HTTP Protocol Basics" module. Document 10 different HTTP headers and their security implications.<br>**Day 3**: Use Burp Repeater to modify requests to httpbin.org. Test all HTTP methods (GET, POST, PUT, DELETE, OPTIONS).<br>**Day 4**: Install OWASP ZAP. Compare proxy features with Burp Suite. Proxy traffic through both tools simultaneously.<br>**Day 5**: Complete "HTTP Request Smuggling" reading (PortSwigger). Practice with httpbin.org/delay endpoint.<br>**Day 6**: Set up Firefox with FoxyProxy. Create profiles for Burp, ZAP, and direct connection. Test profile switching.<br>**Day 7**: Document what you learned. Create a cheat sheet of HTTP status codes (200, 302, 401, 403, 404, 500) and security meanings. | • Burp Suite Community<br>• OWASP ZAP<br>• PortSwigger Academy (free)<br>• httpbin.org<br>• MDN Web Docs - HTTP | Can intercept, modify, and replay HTTP requests using Burp Suite. Understands status codes and headers. | Must master HTTP before vulnerabilities          |
| **Week 2: HTML, JavaScript & Browser Basics**        | **Day 1**: Complete "HTML Basics" on MDN. Build a simple form with 5 input types. View source in browser dev tools.<br>**Day 2**: Complete "JavaScript First Steps" (MDN). Modify JavaScript on live websites using browser console.<br>**Day 3**: Study DOM manipulation. Use console to change page content on 3 different websites. Document methods used.<br>**Day 4**: Learn about cookies, localStorage, sessionStorage. View and modify cookies on reddit.com using dev tools.<br>**Day 5**: Complete "Browser Security Model" reading (MDN). Understand Same-Origin Policy. Test cross-origin restrictions.<br>**Day 6**: Practice Chrome DevTools Network tab. Analyze requests on a news website. Identify API calls vs page loads.<br>**Day 7**: Build a simple HTML page with form, JavaScript validation, and cookie storage. Host locally with Python http.server.                                                                             | • MDN Learn Web Development<br>• Browser DevTools<br>• Python http.server                                       | Can read HTML/JS code, use browser DevTools proficiently, understands how browsers execute code.        | Need to understand client-side before testing it |
| **Week 3: Server-Side Basics & Web Architecture**    | **Day 1**: Install XAMPP/WAMP. Set up local Apache + PHP + MySQL environment. Create "Hello World" PHP page.<br>**Day 2**: Learn basic SQL. Complete SQLBolt lessons 1-5. Practice SELECT, WHERE, JOIN queries.<br>**Day 3**: Build a simple PHP form that inserts data into MySQL. Test form submission and view data in database.<br>**Day 4**: Study session management. Implement PHP sessions. Track user state across page refreshes.<br>**Day 5**: Learn about authentication basics. Create login form (insecure version - you'll secure it later).<br>**Day 6**: Read "How Web Applications Work" (OWASP). Diagram request flow: Browser → Server → Database → Response.<br>**Day 7**: Deploy your PHP app to a free hosting platform (InfinityFree/000webhost). Test remotely.                                                                                                                                                                     | • XAMPP/WAMP<br>• SQLBolt<br>• PHP.net documentation<br>• Free PHP hosting<br>• OWASP "How Web Apps Work"       | Has a working local web server. Understands client-server architecture. Can write basic PHP/SQL.        | Must know how apps work to know how they break   |
| **Week 4: First Vulnerability Hunt & Documentation** | **Day 1**: Set up DVWA (Damn Vulnerable Web Application) locally. Set security to "low". Explore all modules.<br>**Day 2**: Complete DVWA Brute Force module. Document attack steps. Screenshot results.<br>**Day 3**: Complete DVWA Command Injection module. Test different OS commands. Understand why it works.<br>**Day 4**: Complete DVWA File Upload module. Upload PHP shell. Execute commands through uploaded file.<br>**Day 5**: Test your own PHP application from Week 3 for vulnerabilities. Find at least 2 issues.<br>**Day 6**: Write your first vulnerability report using this template: Title, Severity, Description, Steps to Reproduce, Impact, Remediation.<br>**Day 7**: SIMULATION: Scan your digital signage company's internal test environment (with permission). Document findings even if none found.                                                                                                                          | • DVWA<br>• Vulnerability Report Template (Bugcrowd/HackerOne format)<br>• Internal test environment            | Completed first 3 DVWA modules. Written first professional vulnerability report.                        | Apply Month 1 knowledge practically              |

**Month 1 Completion Criteria**: ✅ Can intercept and modify HTTP traffic confidently  
✅ Understands basic web architecture (client-server-database)  
✅ Has exploited 3+ vulnerabilities in DVWA  
✅ Written first structured vulnerability report

**Anti-Paralysis Protocol**: If stuck or unmotivated, default to: "Open Burp Suite, proxy any website, spend 30 minutes just observing traffic."

---

## MONTH 2: OWASP Top 10 Deep Dive (Injection & Broken Authentication)

**Why Now**: Month 1 built foundations. Now systematically learn the most critical vulnerabilities. Start with injection (most common) and authentication (most impactful).

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: SQL Injection Mastery**|**Day 1**: PortSwigger Academy - "SQL Injection" learning path. Complete "What is SQL injection?" module.<br>**Day 2**: Complete "Retrieving Hidden Data" and "Subverting Application Logic" labs (PortSwigger).<br>**Day 3**: Complete "UNION attacks" labs. Practice determining column count and data types.<br>**Day 4**: Complete "Examining the database" labs. Extract database version, table names, column names.<br>**Day 5**: Complete "Blind SQL Injection" labs. Understand Boolean-based vs time-based detection.<br>**Day 6**: DVWA SQL Injection module - Complete on Low, Medium, High security levels. Document bypasses.<br>**Day 7**: SQLMap tutorial. Run automated scans against DVWA. Compare manual vs automated results.|• PortSwigger SQL Injection path (17 labs)<br>• DVWA<br>• SQLMap<br>• SQL Injection cheat sheet|Completed all PortSwigger SQL injection labs. Can manually exploit SQL injection in DVWA at all security levels.|SQLi is #1 for data breaches - master it first|
|**Week 2: Advanced Injection Techniques**|**Day 1**: PortSwigger Academy - "OS Command Injection" module. Complete all 5 labs.<br>**Day 2**: DVWA Command Injection - Complete all security levels. Test blind command injection techniques.<br>**Day 3**: Learn XXE (XML External Entity) attacks. PortSwigger XXE labs 1-4.<br>**Day 4**: Complete LDAP injection reading (OWASP). Test on vulnerable LDAP apps if available.<br>**Day 5**: Learn NoSQL injection basics. Complete "NoSQL Injection" module (PortSwigger).<br>**Day 6**: Study Server-Side Template Injection (SSTI). Complete PortSwigger SSTI labs 1-3.<br>**Day 7**: Create injection attack cheat sheet. Document payloads for SQL, OS, XXE, NoSQL.|• PortSwigger Academy modules<br>• DVWA<br>• PayloadsAllTheThings GitHub<br>• HackTricks injection guides|Can identify and exploit 5+ injection types. Has personal payload cheat sheet.|Injection variations - same root cause|
|**Week 3: Authentication & Session Management**|**Day 1**: PortSwigger "Authentication" learning path - Complete "Password-based login" vulnerabilities.<br>**Day 2**: Complete "Multi-factor authentication" bypass labs (PortSwigger).<br>**Day 3**: Complete "Other authentication mechanisms" labs - Remember me, password reset vulnerabilities.<br>**Day 4**: DVWA Brute Force - Test rate limiting, account lockout. Use Burp Intruder for attacks.<br>**Day 5**: Study session fixation, session hijacking. Complete PortSwigger "Session Management" labs.<br>**Day 6**: Learn about JWT (JSON Web Tokens). Complete jwt.io debugger tutorial. Test jwt_tool.<br>**Day 7**: Set up Juice Shop (OWASP). Complete authentication-related challenges (5+).|• PortSwigger Authentication path (14 labs)<br>• DVWA<br>• jwt_tool<br>• OWASP Juice Shop<br>• Burp Intruder|Completed PortSwigger authentication labs. Understands JWT structure. Bypassed authentication in Juice Shop 5+ times.|Auth bugs = account takeover - critical skill|
|**Week 4: Practical Testing & First Internal Assessment**|**Day 1**: Review Month 2 vulnerabilities. Create testing checklist for injection + authentication.<br>**Day 2**: Test Juice Shop comprehensively. Find 10+ vulnerabilities. Document with screenshots.<br>**Day 3**: Write 3 detailed vulnerability reports for Juice Shop findings. Practice severity assessment (CVSS basics).<br>**Day 4**: SIMULATION: Request access to a non-production internal app at work. Perform time-boxed assessment (60 min).<br>**Day 5**: Document internal assessment findings (even if no vulns found). Focus on methodology used.<br>**Day 6**: Learn about vulnerability databases. Search CVE, NVD, ExploitDB for SQLi and auth bypass examples.<br>**Day 7**: Create Month 2 summary: Techniques learned, tools used, challenges faced, areas for improvement.|• Juice Shop<br>• CVSS Calculator<br>• CVE/NVD/ExploitDB<br>• Internal app (with permission)<br>• Vulnerability report template|3 professional vulnerability reports written. Completed first internal security test.|Apply Month 2 knowledge in realistic scenario|

**Month 2 Completion Criteria**:  
✅ Can manually exploit SQL injection without tools  
✅ Understands authentication mechanisms and common bypasses  
✅ Has tested 2 full applications (Juice Shop + internal)  
✅ Written 3+ professional vulnerability reports

**Stuck Protocol**: If unable to solve a lab after 30 minutes, read the solution, reproduce it, then re-attempt from scratch.

---

## MONTH 3: XSS, CSRF & Client-Side Security

**Why Now**: Injection and auth covered server-side. Now master client-side attacks (XSS is #2 most common vulnerability).

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Cross-Site Scripting (XSS) Fundamentals**|**Day 1**: PortSwigger "Cross-site scripting" path - Complete "What is XSS?" and "Reflected XSS" labs.<br>**Day 2**: Complete "Stored XSS" and "DOM XSS" labs (PortSwigger). Understand the 3 XSS types.<br>**Day 3**: Complete "XSS Contexts" labs - Breaking out of HTML, JS, and attribute contexts.<br>**Day 4**: DVWA XSS (Reflected) - Complete all security levels. Practice filter bypasses.<br>**Day 5**: DVWA XSS (Stored) - Complete all security levels. Test persistence and impact.<br>**Day 6**: Learn XSS payloads from PayloadsAllTheThings. Test cookie stealing, keylogging, page defacement.<br>**Day 7**: Set up XSS Hunter (free tier) or Burp Collaborator. Practice blind XSS detection.|• PortSwigger XSS path (20+ labs)<br>• DVWA<br>• XSS Hunter / Burp Collaborator<br>• PayloadsAllTheThings XSS|Completed all PortSwigger XSS labs. Can bypass common XSS filters. Understands context-specific exploitation.|XSS is critical for account takeover chains|
|**Week 2: Advanced XSS & Content Security Policy**|**Day 1**: Complete PortSwigger "Exploiting XSS vulnerabilities" labs - Session hijacking, credential theft.<br>**Day 2**: Study Content Security Policy (CSP). Complete PortSwigger CSP bypass labs.<br>**Day 3**: Learn DOM Clobbering attacks. Complete related PortSwigger labs.<br>**Day 4**: Practice Mutation XSS (mXSS) techniques. Read research papers on browser parsing differences.<br>**Day 5**: Complete Juice Shop XSS challenges (6+). Test reflected, stored, and DOM-based.<br>**Day 6**: Build XSS payload generator script (Python). Automate encoding/obfuscation.<br>**Day 7**: Document XSS testing methodology. Create decision tree: Input discovery → Context analysis → Payload crafting.|• PortSwigger advanced XSS labs<br>• Juice Shop<br>• Python (for scripting)<br>• CSP Evaluator tool|Can bypass CSP protections. Built custom XSS payload tool. Exploited 6+ XSS variants in Juice Shop.|Master XSS depth before moving to CSRF|
|**Week 3: Cross-Site Request Forgery (CSRF)**|**Day 1**: PortSwigger "CSRF" module - Understand CSRF attack mechanism. Complete basic CSRF labs.<br>**Day 2**: Complete "Bypassing CSRF defenses" labs - Token validation flaws, SameSite cookie bypasses.<br>**Day 3**: DVWA CSRF module - Complete all security levels. Generate CSRF PoCs with Burp Suite.<br>**Day 4**: Learn about CORS (Cross-Origin Resource Sharing). Complete PortSwigger CORS labs.<br>**Day 5**: Study Clickjacking attacks. Complete PortSwigger Clickjacking labs (5+).<br>**Day 6**: Complete WebSockets security labs (PortSwigger). Understand bidirectional communication risks.<br>**Day 7**: Test Juice Shop for CSRF vulnerabilities. Create HTML PoC files for exploitation.|• PortSwigger CSRF path (9 labs)<br>• PortSwigger CORS/Clickjacking<br>• DVWA<br>• Juice Shop<br>• Burp Suite CSRF PoC generator|Completed all CSRF labs. Can generate working PoC exploits. Understands SameSite cookie defenses.|CSRF often chained with XSS - learn together|
|**Week 4: Client-Side Security Testing Practice**|**Day 1**: Install bWAPP (Buggy Web Application). Complete all XSS challenges.<br>**Day 2**: Complete all CSRF and Clickjacking challenges in bWAPP.<br>**Day 3**: Test PentesterLab "XSS and MySQL File" challenge. Practice chaining vulnerabilities.<br>**Day 4**: SIMULATION: Test internal web app for client-side issues. Focus on forms, user inputs, state-changing actions.<br>**Day 5**: Write 2 vulnerability reports for client-side findings (internal or practice apps).<br>**Day 6**: Learn about browser extension security. Analyze a Chrome extension's manifest.json for permissions abuse.<br>**Day 7**: Create Month 3 portfolio entry: Document your best XSS finding with exploitation video/screenshots.|• bWAPP<br>• PentesterLab (free tier)<br>• Internal test app<br>• Chrome extension analysis|Completed bWAPP client-side challenges. Written 2 client-side vulnerability reports. Created portfolio entry.|Synthesize Month 3 knowledge practically|

**Month 3 Completion Criteria**:  
✅ Can identify and exploit XSS in any context  
✅ Understands CSRF and can create PoC exploits  
✅ Has tested 3+ applications for client-side vulnerabilities  
✅ Started security portfolio with documented findings

**Resource Priority Hierarchy**: PortSwigger Labs (highest quality) → DVWA/Juice Shop (practice) → CTF challenges (if time permits).

---

## MONTH 4: Secure Code Review Fundamentals

**Why Now**: After 3 months of exploitation, learn to find vulnerabilities by reading code (critical for AppSec engineers who review PRs).

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Code Review Foundations - PHP**|**Day 1**: Review PHP basics from Month 1. Study common dangerous functions: eval(), system(), exec(), shell_exec().<br>**Day 2**: Analyze vulnerable PHP code from DVWA source on GitHub. Identify SQL injection vulnerabilities in code.<br>**Day 3**: Identify XSS vulnerabilities in DVWA source code. Trace user input from $_GET/$_POST to output.<br>**Day 4**: Learn about input validation vs output encoding. Review PHP filter functions (filter_var, htmlspecialchars).<br>**Day 5**: Install VS Code with PHP security extensions (SonarLint, RIPS Community). Scan DVWA for vulnerabilities.<br>**Day 6**: Review open-source PHP project on GitHub (e.g., WordPress plugin). Document 3 potential security issues.<br>**Day 7**: Create code review checklist for PHP: Input handling, SQL queries, file operations, authentication.|• DVWA source code (GitHub)<br>• VS Code + SonarLint<br>• OWASP Code Review Guide<br>• PHP Security Cheat Sheet|Can identify injection vulnerabilities in PHP code by reading. Has working code review checklist.|Start with familiar language from Month 1|
|**Week 2: Code Review - Python & JavaScript**|**Day 1**: Learn Python security anti-patterns. Study eval(), exec(), pickle, subprocess without shell=False.<br>**Day 2**: Clone vulnerable Python app (e.g., Vulnerable Flask App). Review code for injection points.<br>**Day 3**: Identify authentication flaws in Python code. Look for weak randomness, hardcoded secrets, missing validation.<br>**Day 4**: Study JavaScript security patterns. Focus on: innerHTML vs textContent, eval() dangers, prototype pollution.<br>**Day 5**: Review JavaScript code from Juice Shop (GitHub). Identify client-side validation bypasses.<br>**Day 6**: Learn about npm package security. Use npm audit, Snyk CLI to scan a Node.js project.<br>**Day 7**: Compare findings: Manual code review vs automated tool (SonarQube/Semgrep). Document false positives/negatives.|• Vulnerable Flask App (GitHub)<br>• Juice Shop source code<br>• npm audit / Snyk<br>• Semgrep (free)|Can review Python and JavaScript for common vulnerabilities. Understands limitations of SAST tools.|Expand to other common web languages|
|**Week 3: Advanced Code Review Patterns**|**Day 1**: Study business logic vulnerabilities. Review "Insufficient Workflow Validation" examples (OWASP).<br>**Day 2**: Learn about race conditions in code. Review file upload race condition examples.<br>**Day 3**: Study deserialization vulnerabilities. Review ysoserial payloads, understand Java/Python/PHP deserialization.<br>**Day 4**: Learn about mass assignment vulnerabilities. Review framework-specific examples (Rails, Laravel, Express).<br>**Day 5**: Study Server-Side Request Forgery (SSRF) in code. Identify unsafe HTTP request patterns.<br>**Day 6**: Complete PortSwigger "Insecure Deserialization" and "SSRF" labs to understand exploitation context.<br>**Day 7**: Review a medium-sized open-source project (500-2000 lines). Write findings report as if for development team.|• PortSwigger SSRF/Deserialization labs<br>• GitHub open-source projects<br>• OWASP Business Logic Testing Guide|Completed SSRF and deserialization labs. Can identify business logic flaws in code. Written developer-focused security review.|Advanced patterns rare but high-impact|
|**Week 4: Practical Code Review Simulation**|**Day 1**: Set up SonarQube Community locally. Scan 3 vulnerable apps (DVWA, Juice Shop, custom app).<br>**Day 2**: Review SonarQube findings. Validate true positives by exploiting vulnerabilities.<br>**Day 3**: SIMULATION: Request to review a pull request at work (with permission). Focus on security implications.<br>**Day 4**: Document PR review findings. Use GitHub security advisory format for reporting.<br>**Day 5**: Practice threat modeling basics. Use STRIDE framework to analyze one application feature.<br>**Day 6**: Learn about IDE security plugins. Install and configure: DevSkim, Snyk Code, Checkmarx plugin.<br>**Day 7**: Create Month 4 deliverable: Full security code review report of an open-source project (5-10 pages).|• SonarQube Community<br>• Work codebase (with permission)<br>• STRIDE threat modeling<br>• IDE security extensions|Performed production PR security review. Written comprehensive code review report. Understands SAST tool integration.|Apply Month 4 in realistic workflow|

**Month 4 Completion Criteria**:  
✅ Can identify vulnerabilities by reading code (PHP, Python, JS)  
✅ Understands SAST tool capabilities and limitations  
✅ Has reviewed production code with security lens  
✅ Written developer-friendly security review report

---

## MONTH 5: Access Control & Authorization Deep Dive

**Why Now**: Access control bugs are complex, often missed by automated tools, and critical for AppSec roles. Builds on Month 2 auth knowledge.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Access Control Fundamentals**|**Day 1**: PortSwigger "Access Control" path - Complete "What is access control?" and vertical privilege escalation labs.<br>**Day 2**: Complete horizontal privilege escalation labs. Understand IDOR (Insecure Direct Object Reference).<br>**Day 3**: Complete "Context-dependent access controls" labs - Referer-based, location-based access.<br>**Day 4**: DVWA "Insecure CAPTCHA" - Understand workflow bypass through parameter manipulation.<br>**Day 5**: Study RBAC (Role-Based Access Control) vs ABAC (Attribute-Based). Review implementation examples.<br>**Day 6**: Complete Juice Shop access control challenges (8+). Test user role manipulation.<br>**Day 7**: Create IDOR testing methodology: Identify resources → Enumerate IDs → Test cross-user access.|• PortSwigger Access Control path (13 labs)<br>• DVWA<br>• Juice Shop<br>• OWASP Testing Guide - Authorization|Completed all PortSwigger access control labs. Exploited 8+ access control bugs in Juice Shop.|Foundation before complex scenarios|
|**Week 2: Advanced Authorization Testing**|**Day 1**: Learn about GraphQL authorization issues. Complete PortSwigger GraphQL labs.<br>**Day 2**: Study OAuth 2.0 flows. Complete PortSwigger OAuth authentication labs (5+).<br>**Day 3**: Test for privilege escalation through parameter pollution. Practice with Juice Shop.<br>**Day 4**: Learn about multi-tenancy issues. Review SaaS access control patterns and common bugs.<br>**Day 5**: Study JWT authorization flaws (alg=none, key confusion). Complete jwt_tool challenges.<br>**Day 6**: Practice forced browsing/directory traversal for privilege escalation. Use tools: ffuf, gobuster.<br>**Day 7**: Test HackTheBox "Insecure" machine (or similar) focusing on access control exploitation.|• PortSwigger GraphQL/OAuth labs<br>• jwt_tool<br>• ffuf / gobuster<br>• HackTheBox (free tier)|Can test GraphQL and OAuth implementations. Understands multi-tenancy security. Exploited privilege escalation on HTB.|Real-world auth is complex - cover variations|
|**Week 3: File Upload & Path Traversal**|**Day 1**: PortSwigger "File Upload Vulnerabilities" - Complete all 7 labs. Upload web shells successfully.<br>**Day 2**: PortSwigger "Directory Traversal" - Complete all 6 labs. Read /etc/passwd on vulnerable apps.<br>**Day 3**: DVWA File Upload - Bypass all security levels. Test double extensions, content-type manipulation, magic bytes.<br>**Day 4**: Study unrestricted file upload exploitation. Practice with Upload Labs (GitHub vulnerable app).<br>**Day 5**: Learn about ZIP slip vulnerabilities. Test archive extraction attacks.<br>**Day 6**: Complete XXE labs with a focus on file retrieval through external entities.<br>**Day 7**: Create file upload security checklist: Extension validation, content validation, storage location, execution prevention.|• PortSwigger File Upload/Directory Traversal<br>• DVWA<br>• Upload Labs (GitHub)<br>• File upload security guide|Completed all file upload and path traversal labs. Can bypass common upload restrictions.|File uploads are high-impact access control issues|
|**Week 4: Business Logic & Access Control Testing**|**Day 1**: Study price manipulation vulnerabilities. Test Juice Shop for payment bypass.<br>**Day 2**: Learn about workflow bypass attacks. Test multi-step processes for step skipping.<br>**Day 3**: Practice API access control testing. Use Postman to test different user roles on same endpoints.<br>**Day 4**: SIMULATION: Test internal app for IDOR vulnerabilities. Document user context switching methodology.<br>**Day 5**: Write 2 access control vulnerability reports. Focus on business impact assessment.<br>**Day 6**: Review OWASP ASVS (Application Security Verification Standard) Section 4 (Access Control).<br>**Day 7**: Create Month 5 deliverable: Access control testing guide for your organization (template format).|• Juice Shop<br>• Postman<br>• Internal test app<br>• OWASP ASVS<br>• Vulnerability report template|Tested internal app for access control. Written 2 reports. Created organizational testing guide.|Synthesize into reusable methodology|

**Month 5 Completion Criteria**:  
✅ Can identify complex access control vulnerabilities  
✅ Understands OAuth, GraphQL, and API authorization  
✅ Has created organizational security testing templates  
✅ Tested 4+ applications for authorization flaws

---

## 🔄 MIDPOINT EVALUATION CHECKPOINT (After Month 5)

**Objective Readiness Assessment**:

|Capability|Self-Test|Pass Criteria|
|---|---|---|
|**HTTP/Web Fundamentals**|Explain client-server flow, intercept HTTPS traffic, modify requests|Can do without references|
|**OWASP Top 10 Knowledge**|Exploit SQLi, XSS, CSRF, Auth Bypass, Access Control blind (no hints)|4/5 success rate|
|**Code Review**|Find 3+ vulnerabilities in unfamiliar 500-line codebase|Within 60 minutes|
|**Reporting**|Write professional vulnerability report|Passes peer review|
|**Tooling**|Use Burp Suite, OWASP ZAP, SQLMap, code scanner without documentation|Proficient operation|

**Decision Point**:

- ✅ **Pass all criteria** → Continue to Month 6 (API Security)
- ⚠️ **Fail 1-2 criteria** → Spend 2 weeks reinforcing weak areas using PortSwigger labs + practice apps
- ❌ **Fail 3+ criteria** → Restart Month 3-5 with increased hands-on practice time

**Portfolio Check**: By now you should have:

- 10+ vulnerability reports
- 2-3 tested applications documented
- Code review samples
- Testing methodology documents

---

## MONTH 6: API Security & Modern Application Testing

**Why Now**: APIs dominate modern apps. After mastering web fundamentals, learn API-specific attack vectors.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: REST API Fundamentals**|**Day 1**: Learn REST API basics. Study HTTP methods in API context. Use Postman to interact with public APIs (GitHub, JSONPlaceholder).<br>**Day 2**: PortSwigger "API Testing" module - Complete API recon and documentation discovery labs.<br>**Day 3**: Complete "Mass assignment" API labs (PortSwigger). Understand JSON parameter pollution.<br>**Day 4**: Study OWASP API Security Top 10 (2023). Compare to OWASP Web Top 10.<br>**Day 5**: Set up crAPI (Completely Ridiculous API) locally. Explore API endpoints with Burp Suite.<br>**Day 6**: Complete crAPI Challenge 1-3. Document API-specific testing approach vs web testing.<br>**Day 7**: Install Postman Collections from OWASP API Security Project. Practice API fuzzing.|• Postman<br>• PortSwigger API Testing<br>• crAPI (OWASP)<br>• OWASP API Security Top 10 2023|Completed PortSwigger API labs. Solved 3 crAPI challenges. Understands API Top 10.|APIs are different attack surface than web UIs|
|**Week 2: Advanced API Testing**|**Day 1**: Study GraphQL security. Complete PortSwigger GraphQL labs (all 5).<br>**Day 2**: Learn GraphQL introspection, batching attacks, depth limiting bypass.<br>**Day 3**: Test Damn Vulnerable GraphQL Application (DVGA). Complete 5+ challenges.<br>**Day 4**: Study REST API rate limiting bypass techniques. Test crAPI for rate limit issues.<br>**Day 5**: Learn about API versioning vulnerabilities. Test deprecated endpoints for security issues.<br>**Day 6**: Practice JWT testing with jwt_tool. Test algorithm confusion, weak secrets, claim manipulation.<br>**Day 7**: Create API security testing checklist: Authentication, Authorization, Rate limiting, Input validation, Error handling.|• PortSwigger GraphQL labs<br>• DVGA (Damn Vulnerable GraphQL App)<br>• crAPI<br>• jwt_tool|Completed all GraphQL labs. Solved 5 DVGA challenges. Can test JWT implementations.|GraphQL increasingly common - master it|
|**Week 3: API Automation & Tooling**|**Day 1**: Learn Burp Suite extensions for API testing: JSON Beautifier, Autorize, JSON Web Tokens.<br>**Day 2**: Install and configure OWASP ZAP API Scan. Run automated API scan against crAPI.<br>**Day 3**: Study Swagger/OpenAPI specifications. Extract API documentation from applications.<br>**Day 4**: Learn Postman automation. Create pre-request scripts for authentication token handling.<br>**Day 5**: Practice with Arjun (HTTP parameter discovery tool). Find hidden API parameters.<br>**Day 6**: Test API with fuzzing tools: wfuzz, ffuf. Focus on parameter enumeration.<br>**Day 7**: Build simple Python script to automate API endpoint enumeration using requests library.|• Burp Suite extensions<br>• OWASP ZAP API Scan<br>• Postman scripting<br>• Arjun, wfuzz, ffuf<br>• Python requests|Automated API testing workflow established. Built custom enumeration script.|Automation critical for API security at scale|
|**Week 4: Real-World API Testing**|**Day 1**: Complete all remaining crAPI challenges (aim for 10+ total).<br>**Day 2**: Test vAPI (Vulnerable API) - Complete all modules. Compare to crAPI.<br>**Day 3**: SIMULATION: Identify APIs in internal applications. Map endpoints using Burp Suite passive scanning.<br>**Day 4**: Test internal API for authentication/authorization issues. Document methodology used.<br>**Day 5**: Write API security testing report for internal findings. Include OpenAPI spec documentation.<br>**Day 6**: Study microservices security. Review service mesh concepts (Istio, Linkerd) and security implications.<br>**Day 7**: Create Month 6 deliverable: "API Security Testing Playbook" - Step-by-step guide for your organization.|• crAPI<br>• vAPI<br>• Internal APIs<br>• Service mesh documentation<br>• Report template|Completed crAPI and vAPI. Tested internal API. Written API-specific testing playbook.|Apply to production-like scenarios|

**Month 6 Completion Criteria**:  
✅ Can test REST and GraphQL APIs comprehensively  
✅ Understands API-specific vulnerabilities (OWASP API Top 10)  
✅ Has automated API testing workflow  
✅ Created organizational API testing playbook

---

## MONTH 7: Secure SDLC & DevSecOps Integration

**Why Now**: AppSec engineers integrate security into development workflows. Learn where/how to insert security into CI/CD pipelines.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: SDLC & Security Integration Basics**|**Day 1**: Study Secure SDLC models: Microsoft SDL, OWASP SAMM, BSIMM. Compare approaches.<br>**Day 2**: Learn DevSecOps principles. Watch "DevSecOps Explained" talks on YouTube (OWASP AppSec conferences).<br>**Day 3**: Study shift-left security. Understand difference between design review, code review, testing phases.<br>**Day 4**: Learn about threat modeling. Practice STRIDE on a simple web application feature.<br>**Day 5**: Complete Microsoft Threat Modeling Tool tutorial. Create threat model for login functionality.<br>**Day 6**: Study security requirements gathering. Review OWASP ASVS for requirement examples.<br>**Day 7**: Create security user stories template. Map ASVS requirements to agile user story format.|• OWASP SAMM<br>• Microsoft SDL<br>• Microsoft Threat Modeling Tool<br>• OWASP ASVS<br>• DevSecOps talks|Understands Secure SDLC phases. Completed threat model. Created security requirements template.|Foundation before technical implementation|
|**Week 2: Static Application Security Testing (SAST)**|**Day 1**: Compare SAST tools: SonarQube, Semgrep, Checkmarx, Veracode. Understand commercial vs open-source.<br>**Day 2**: Set up Semgrep locally. Create custom rules for your organization's code patterns.<br>**Day 3**: Integrate SonarQube with GitHub repository. Configure quality gates for security findings.<br>**Day 4**: Study SAST false positive management. Triage 20+ SonarQube findings (true vs false positive).<br>**Day 5**: Learn about IDE security plugins. Configure SonarLint for VS Code with custom rules.<br>**Day 6**: Practice pre-commit hooks. Set up git hooks to run security checks before code commit.<br>**Day 7**: Document SAST integration guide: Tool selection, configuration, developer training, triage workflow.|• Semgrep<br>• SonarQube<br>• SonarLint<br>• GitHub Actions/pre-commit<br>• False positive analysis|Integrated SAST into development workflow. Created custom security rules. Documented triage process.|SAST is primary AppSec tool - master it|
|**Week 3: Dynamic & Interactive Testing (DAST/IAST)**|**Day 1**: Study DAST vs SAST differences. Understand when each is appropriate.<br>**Day 2**: Set up OWASP ZAP in daemon mode. Configure for CI/CD integration.<br>**Day 3**: Create ZAP automation framework configuration. Run automated scans via API.<br>**Day 4**: Learn about StackHawk (modern DAST tool). Complete StackHawk tutorial for API scanning.<br>**Day 5**: Study IAST (Interactive Application Security Testing). Review Contrast Security documentation.<br>**Day 6**: Compare SAST/DAST/IAST coverage. Create Venn diagram of vulnerability detection capabilities.<br>**Day 7**: Build simple CI/CD pipeline (GitHub Actions) with ZAP scanning. Test against DVWA.|• OWASP ZAP daemon mode<br>• StackHawk (free tier)<br>• GitHub Actions<br>• IAST vendor docs|Integrated DAST into CI/CD pipeline. Understands tool coverage gaps. Built working security pipeline.|Complement SAST with runtime testing|
|**Week 4: Software Composition Analysis & Supply Chain**|**Day 1**: Learn about SCA (Software Composition Analysis). Study dependency vulnerabilities.<br>**Day 2**: Use OWASP Dependency-Check. Scan a Node.js project for vulnerable dependencies.<br>**Day 3**: Practice with Snyk CLI. Integrate Snyk into GitHub repository.<br>**Day 4**: Study software supply chain attacks. Review SolarWinds, Log4Shell incidents.<br>**Day 5**: Learn about SBOM (Software Bill of Materials). Generate SBOM using Syft/CycloneDX.<br>**Day 6**: SIMULATION: Analyze dependencies in internal project. Report outdated/vulnerable libraries.<br>**Day 7**: Create Month 7 deliverable: "AppSec Pipeline Blueprint" - Complete CI/CD security integration architecture.|• OWASP Dependency-Check<br>• Snyk<br>• Syft/CycloneDX<br>• Supply chain security guides<br>• Internal project|Integrated SCA into workflow. Generated SBOM. Created comprehensive security pipeline document.|Supply chain is modern critical risk|

**Month 7 Completion Criteria**:  
✅ Understands Secure SDLC and DevSecOps principles  
✅ Integrated SAST, DAST, SCA into CI/CD pipeline  
✅ Can create threat models and security requirements  
✅ Built working security automation pipeline

---

## MONTH 8: Cloud Security & Container Security

**Why Now**: Modern apps run in cloud/containers. AppSec roles require understanding cloud-native security.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Cloud Fundamentals & IAM**|**Day 1**: Study cloud shared responsibility model (AWS, Azure, GCP). Understand app vs infrastructure security.<br>**Day 2**: Learn AWS IAM basics. Create AWS free tier account. Set up users, groups, roles, policies.<br>**Day 3**: Practice IAM misconfigurations. Complete Flaws.cloud challenge (AWS security CTF).<br>**Day 4**: Study S3 bucket security. Test for public buckets using s3Scanner, grayhatwarfare.<br>**Day 5**: Learn about cloud SSRF. Complete PortSwigger "SSRF" labs with cloud metadata context (169.254.169.254).<br>**Day 6**: Study AWS security services: GuardDuty, SecurityHub, CloudTrail. Review security logging best practices.<br>**Day 7**: Complete CloudGoat scenarios 1-2 (Rhino Security Labs' vulnerable AWS environment).|• AWS Free Tier<br>• Flaws.cloud<br>• CloudGoat<br>• s3Scanner<br>• PortSwigger SSRF labs|Completed Flaws.cloud. Solved 2 CloudGoat scenarios. Understands cloud IAM principles.|Cloud IAM is foundation for cloud security|
|**Week 2: Container Security**|**Day 1**: Learn Docker basics. Install Docker Desktop. Build and run containers from Dockerfiles.<br>**Day 2**: Study container security risks. Review CIS Docker Benchmark. Scan containers with Docker Bench.<br>**Day 3**: Practice container escape techniques. Complete "Hacker Container" challenges (GitHub).<br>**Day 4**: Learn about image scanning. Use Trivy, Grype to scan container images for vulnerabilities.<br>**Day 5**: Study Kubernetes security basics. Set up local Kubernetes with Minikube. Deploy vulnerable pods.<br>**Day 6**: Complete Kubernetes Goat scenarios (OWASP). Focus on pod security policies, RBAC.<br>**Day 7**: Integrate container scanning into CI/CD. Add Trivy scan to GitHub Actions workflow.|• Docker Desktop<br>• Docker Bench<br>• Trivy / Grype<br>• Kubernetes Goat (OWASP)<br>• Minikube|Completed container security challenges. Integrated image scanning into CI/CD. Understands K8s security.|Containers are standard deployment model|
|**Week 3: Serverless & Cloud-Native Security**|**Day 1**: Study serverless security (AWS Lambda, Azure Functions). Learn function-specific attack vectors.<br>**Day 2**: Complete ServerlessGoat scenarios (OWASP). Exploit Lambda misconfigurations.<br>**Day 3**: Learn about API Gateway security. Test authentication/authorization in serverless architectures.<br>**Day 4**: Study secrets management. Practice with AWS Secrets Manager, HashiCorp Vault.<br>**Day 5**: Learn about Infrastructure as Code (IaC) security. Scan Terraform files with tfsec, Checkov.<br>**Day 6**: Practice cloud enumeration. Use ScoutSuite, Prowler for AWS security assessment.<br>**Day 7**: Document cloud security testing checklist: IAM, storage, compute, network, logging.|• ServerlessGoat<br>• AWS Lambda<br>• tfsec / Checkov<br>• ScoutSuite / Prowler<br>• Cloud security guides|Completed serverless security scenarios. Can scan IaC for security issues.|Serverless increasingly common architecture|
|**Week 4: Cloud Security Simulation**|**Day 1**: SIMULATION: Request access to cloud resources at work (staging/dev environment).<br>**Day 2**: Perform cloud security assessment: IAM review, storage configuration, logging verification.<br>**Day 3**: Test cloud-hosted applications for cloud-specific vulnerabilities (SSRF to metadata, overprivileged IAM).<br>**Day 4**: Write cloud security assessment report. Include remediation guidance specific to cloud platform.<br>**Day 5**: Study multi-cloud security. Compare AWS, Azure, GCP security services.<br>**Day 6**: Learn about cloud security posture management (CSPM). Review tools: Prisma Cloud, Lacework, Wiz.<br>**Day 7**: Create Month 8 deliverable: "Cloud Application Security Guide" for your organization.|• Work cloud environment<br>• Cloud assessment tools<br>• CSPM vendor docs<br>• Report template|Assessed production cloud environment. Written cloud security report. Created organizational guide.|Apply cloud knowledge practically|

**Month 8 Completion Criteria**:  
✅ Understands cloud security fundamentals (IAM, storage, compute)  
✅ Can assess container and Kubernetes security  
✅ Has tested cloud-native applications  
✅ Integrated IaC scanning into security workflow

---

## 🎯 ADVANCED DIRECTION CHECKPOINT (After Month 8)

**Career Path Assessment**:

You now have core AppSec skills. Choose focus area for Months 9-12:

**Option A: Offensive AppSec (Red Team / Bug Bounty)**

- Focus: Advanced exploitation, chaining vulnerabilities, creative bypasses
- Months 9-12: Web3/blockchain security, advanced chains, bug bounty methodology, CTF practice

**Option B: Defensive AppSec (Blue Team / Security Engineering)**

- Focus: Detection, prevention, secure architecture, tooling development
- Months 9-12: WAF tuning, secure architecture patterns, security automation, metrics/reporting

**Option C: Balanced Enterprise AppSec (Recommended for entry-level roles)**

- Focus: Practical testing, security champions programs, secure development practices
- Months 9-12: Advanced web testing, mobile security basics, security training development, portfolio building

**Default Path**: Option C (Balanced Enterprise AppSec) - Proceeds below

**Readiness Criteria for Months 9-12**:

- ✅ Can independently test complex web applications
- ✅ Understands CI/CD security integration
- ✅ Has written 20+ vulnerability reports
- ✅ Can review code and infrastructure-as-code for security issues

---

## MONTH 9: Advanced Web Testing & Complex Vulnerability Chains

**Why Now**: Entry-level roles require demonstrating depth. Advanced testing shows expertise beyond automated scans.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Business Logic Vulnerabilities**|**Day 1**: PortSwigger "Business Logic Vulnerabilities" - Complete all 11 labs.<br>**Day 2**: Study race condition attacks. Complete "Limit Overrun Race Conditions" labs (PortSwigger).<br>**Day 3**: Learn about price manipulation. Test Juice Shop for payment bypass scenarios.<br>**Day 4**: Practice multi-step workflow attacks. Test registration, checkout, review processes for step skipping.<br>**Day 5**: Study inconsistent security controls. Test for different validation in different code paths.<br>**Day 6**: Complete PentesterLab "Business Logic Flaws" exercises.<br>**Day 7**: Document business logic testing methodology. Create testing templates for common workflows.|• PortSwigger Business Logic path<br>• Juice Shop<br>• PentesterLab<br>• Testing templates|Completed all business logic labs. Can identify workflow bypasses. Created testing templates.|Business logic often missed by scanners|
|**Week 2: Advanced Authentication Attacks**|**Day 1**: Study password reset poisoning. Complete PortSwigger "Password Reset Poisoning" labs.<br>**Day 2**: Learn about 2FA bypass techniques. Test TOTP, SMS, email-based 2FA implementations.<br>**Day 3**: Practice account takeover chains. Combine XSS + CSRF + session fixation.<br>**Day 4**: Study OAuth misconfiguration exploitation. Complete advanced OAuth labs (PortSwigger).<br>**Day 5**: Learn about subdomain takeover. Practice with can-i-take-over-xyz (GitHub).<br>**Day 6**: Test SAML authentication. Complete SAML Raider plugin tutorial for Burp Suite.<br>**Day 7**: Create account takeover attack tree. Map all possible ATO paths in typical application.|• PortSwigger advanced auth labs<br>• can-i-take-over-xyz<br>• SAML Raider<br>• Attack tree methodology|Completed advanced authentication labs. Can chain multiple vulnerabilities for account takeover.|ATO is critical business impact - master it|
|**Week 3: Advanced Injection & Data Exfiltration**|**Day 1**: Study second-order SQL injection. Complete PortSwigger "Second-Order SQL Injection" labs.<br>**Day 2**: Learn about blind injection optimization. Practice with time-based SQLi using sqlmap --technique=T.<br>**Day 3**: Study OOB (out-of-band) data exfiltration. Use Burp Collaborator for DNS/HTTP exfiltration.<br>**Day 4**: Practice advanced XXE. Complete "Blind XXE" labs (PortSwigger).<br>**Day 5**: Learn about SSTI exploitation. Test with tplmap tool. Practice RCE through template injection.<br>**Day 6**: Study command injection filter bypasses. Test encoding, concatenation, wildcard bypasses.<br>**Day 7**: Complete Web Security Academy "Advanced Topics" section (all remaining labs).|• PortSwigger advanced labs<br>• sqlmap advanced<br>• tplmap<br>• Burp Collaborator|Completed advanced injection labs. Can perform OOB exfiltration. Exploited SSTI for RCE.|Advanced techniques for mature targets|
|**Week 4: Vulnerability Chaining Practice**|**Day 1**: Study vulnerability chaining methodology. Review real-world chain examples (HackerOne reports).<br>**Day 2**: Practice chaining: Self-XSS → CSRF → Stored XSS → Account Takeover.<br>**Day 3**: Chain SSRF + XXE for internal network access. Practice on vulnerable lab environments.<br>**Day 4**: SIMULATION: Perform advanced testing on internal application. Goal: Find vulnerability chain.<br>**Day 5**: Write detailed chain report. Include attack narrative, technical details, business impact.<br>**Day 6**: Complete HackTheBox Pro Labs "Dante" or similar multi-vulnerability scenario.<br>**Day 7**: Create Month 9 deliverable: Advanced vulnerability report with chain exploitation documented.|• HackerOne disclosed reports<br>• HackTheBox Pro Labs<br>• Internal application<br>• Advanced report template|Found and documented vulnerability chain. Completed advanced lab. Written professional advanced report.|Chains demonstrate real skill vs scanner use|

**Month 9 Completion Criteria**:  
✅ Can identify business logic vulnerabilities  
✅ Can chain multiple vulnerabilities for high-impact exploitation  
✅ Has completed advanced PortSwigger labs  
✅ Written advanced technical security report

---

## MONTH 10: Mobile Application Security Basics

**Why Now**: Many organizations have mobile apps. Basic mobile AppSec knowledge makes you more competitive.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Android Security Fundamentals**|**Day 1**: Study Android architecture. Understand APK structure, manifest, permissions model.<br>**Day 2**: Set up Android testing environment: Android Studio, Android emulator, ADB.<br>**Day 3**: Install DIVA (Damn Insecure and Vulnerable App). Complete "Insecure Logging" challenge.<br>**Day 4**: Learn APK decompilation. Use jadx, apktool to reverse engineer DIVA.<br>**Day 5**: Complete DIVA "Hardcoding Issues" challenges. Find secrets in decompiled code.<br>**Day 6**: Study Android SSL pinning. Complete DIVA "Input Validation" challenges.<br>**Day 7**: Install MobSF (Mobile Security Framework). Scan DIVA and review automated findings.|• Android Studio<br>• DIVA<br>• jadx / apktool<br>• MobSF<br>• OWASP Mobile Top 10|Completed DIVA challenges. Can decompile and analyze APKs. Understands Android security model.|Android dominates enterprise mobile|
|**Week 2: Advanced Android Testing**|**Day 1**: Learn Frida framework basics. Install Frida server on Android emulator.<br>**Day 2**: Practice Frida hooking. Bypass DIVA SSL pinning using Frida scripts.<br>**Day 3**: Study Android WebView vulnerabilities. Test for JavaScript injection in WebViews.<br>**Day 4**: Learn about intent-based vulnerabilities. Complete intent redirection challenges.<br>**Day 5**: Practice with InjuredAndroid (CTF app). Complete levels 1-5.<br>**Day 6**: Test for insecure data storage. Analyze app databases, shared preferences, external storage.<br>**Day 7**: Create Android security testing checklist based on OWASP Mobile Top 10.|• Frida<br>• InjuredAndroid<br>• Drozer (intent testing)<br>• OWASP Mobile Top 10 2024|Can use Frida for dynamic analysis. Completed 5 InjuredAndroid levels. Created mobile testing checklist.|Dynamic instrumentation is key skill|
|**Week 3: iOS Security Basics (Optional/Survey)**|**Day 1**: Study iOS security model. Compare to Android (sandboxing, permissions, app store review).<br>**Day 2**: Learn about iOS app structure (.ipa files, binary protection, code signing).<br>**Day 3**: Review DVIA (Damn Vulnerable iOS App) challenge list. Study solutions (if no Mac/iOS device).<br>**Day 4**: Study iOS-specific vulnerabilities: Keychain misuse, URL scheme hijacking, insecure IPC.<br>**Day 5**: Learn about jailbreak detection bypass. Review common techniques.<br>**Day 6**: Compare mobile testing tools: Objection, MobSF, Needle (iOS), Frida.<br>**Day 7**: Document iOS vs Android security differences. Create comparison matrix.|• OWASP Mobile Top 10<br>• DVIA documentation<br>• iOS security guides<br>• Comparison research|Understands iOS security fundamentals. Can explain iOS vs Android differences.|Awareness even without testing capability|
|**Week 4: Mobile API & Backend Testing**|**Day 1**: Study mobile API testing. Set up proxy for mobile app traffic (Burp Suite + Android).<br>**Day 2**: Test DIVA backend APIs. Capture and replay API requests.<br>**Day 3**: Practice API parameter manipulation for mobile apps. Test for IDOR, privilege escalation.<br>**Day 4**: Learn about mobile certificate pinning bypass. Use Frida or SSL Kill Switch.<br>**Day 5**: SIMULATION: Request to test internal mobile app (or publicly available app with permission).<br>**Day 6**: Write mobile security assessment report. Focus on API security findings.<br>**Day 7**: Create Month 10 deliverable: "Mobile Application Security Testing Guide" for beginners.|• Burp Suite + mobile cert<br>• SSL Kill Switch 2<br>• Mobile app for testing<br>• Report template|Intercepted mobile app traffic. Tested mobile APIs. Written mobile security report.|Mobile backend often overlooked|

**Month 10 Completion Criteria**:  
✅ Can perform basic Android security testing  
✅ Understands mobile-specific vulnerabilities  
✅ Can intercept and test mobile app APIs  
✅ Written mobile security assessment report

**Note**: Month 10 is exposure, not mastery. Mobile requires dedicated learning path for specialization.

---

## MONTH 11: Professional Skills & Portfolio Development

**Why Now**: Technical skills proven. Now build communication, reporting, and portfolio for job applications.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Professional Reporting & Communication**|**Day 1**: Study professional vulnerability report formats. Review HackerOne, Bugcrowd disclosure templates.<br>**Day 2**: Rewrite 3 old vulnerability reports to professional standard. Add CVSS scoring, business impact.<br>**Day 3**: Learn about CVSS (Common Vulnerability Scoring System). Practice scoring 10 vulnerabilities.<br>**Day 4**: Study effective remediation advice. Review OWASP cheat sheets. Rewrite remediation sections.<br>**Day 5**: Practice developer-friendly communication. Create "developer explanation" vs "security team explanation" formats.<br>**Day 6**: Learn about vulnerability disclosure ethics. Study coordinated disclosure policies.<br>**Day 7**: Create executive summary template. Write 1-page summary of complex technical finding.|• HackerOne reports<br>• CVSS Calculator<br>• OWASP Cheat Sheets<br>• Report templates|3 professional-grade reports written. Can calculate CVSS scores. Created executive summary template.|Communication as important as technical skill|
|**Week 2: Security Portfolio Development**|**Day 1**: Set up professional portfolio. Create GitHub Pages site or personal website.<br>**Day 2**: Write "About Me" and "Skills" sections. Document learning journey from Month 1-11.<br>**Day 3**: Document 5 best vulnerability findings (sanitized, no sensitive info). Include impact, exploitation, remediation.<br>**Day 4**: Create "Projects" section. Document custom tools, scripts, testing frameworks built.<br>**Day 5**: Write blog post: "My 11-Month Journey to Application Security Engineering".<br>**Day 6**: Create case study: "How I Secured [Internal App Name]" - Redact sensitive details.<br>**Day 7**: Review and polish portfolio. Get feedback from r/netsec, r/AskNetsec communities.|• GitHub Pages / Hugo / Jekyll<br>• Portfolio examples<br>• Technical writing guides<br>• Reddit communities|Live security portfolio published. 5 findings documented. 1 blog post written.|Portfolio demonstrates capability to employers|
|**Week 3: Bug Bounty & Continuous Learning**|**Day 1**: Study bug bounty methodology. Review "The Bug Hunter's Methodology" by Jason Haddix.<br>**Day 2**: Sign up for bug bounty platforms: HackerOne, Bugcrowd, Intigriti (free tiers).<br>**Day 3**: Choose 1 bug bounty program (preferably educational/VDP). Read scope, perform reconnaissance.<br>**Day 4**: Test chosen program for 90 minutes. Focus on one vulnerability type (e.g., all XSS).<br>**Day 5**: If finding discovered, write report. If not, document testing methodology used.<br>**Day 6**: Join security communities: OWASP Slack, Bug Bounty Forum, r/websecurity Discord.<br>**Day 7**: Create continuous learning plan: Weekly newsletters (tl;dr sec), podcasts, conferences to follow.|• Bug bounty platforms<br>• Jason Haddix methodology<br>• Security communities<br>• Learning resources|Joined bug bounty platform. Tested 1 program. Engaged with security community.|Real-world practice + networking|
|**Week 4: Interview Preparation & Career Planning**|**Day 1**: Research AppSec job descriptions. Identify common requirements. Map your skills to requirements.<br>**Day 2**: Practice technical interview questions. Review "Application Security Interview Questions" (GitHub).<br>**Day 3**: Prepare "Tell me about yourself" and "Why AppSec?" answers. Record and review.<br>**Day 4**: Study common scenarios: "How would you test a login page?", "Explain CSRF to a developer".<br>**Day 5**: Update resume. Highlight: 11-month learning journey, internal testing experience, portfolio projects.<br>**Day 6**: Update LinkedIn. Add skills, certifications (if any), portfolio link. Write security-focused summary.<br>**Day 7**: Create Month 11 deliverable: Interview preparation document with answers to 20 common questions.|• Job postings research<br>• Interview question repos<br>• Resume templates<br>• LinkedIn optimization|Resume updated. LinkedIn optimized. Interview prep document created. Portfolio complete.|Prepare for job application phase|

**Month 11 Completion Criteria**:  
✅ Professional security portfolio published online  
✅ 5+ documented vulnerability findings  
✅ Engaged with security community  
✅ Interview-ready resume and preparation

---

## MONTH 12: Advanced Practice & Job Application

**Why Now**: Final month focused on demonstrating readiness through comprehensive testing and active job hunting.

|Week|Daily Tasks (90 min/day)|Resources|Completion Criteria|Why This Week|
|---|---|---|---|---|
|**Week 1: Comprehensive Application Assessment**|**Day 1**: Choose complex vulnerable application (Mutillidae II, WebGoat 8, or Bug Bounty target).<br>**Day 2**: Perform reconnaissance. Map attack surface: endpoints, parameters, technologies, user roles.<br>**Day 3**: Test for all OWASP Top 10 vulnerabilities. Document findings as you discover.<br>**Day 4**: Test for API security issues. Test for cloud misconfigurations (if applicable).<br>**Day 5**: Test for business logic flaws. Analyze workflows, payment processes, privilege models.<br>**Day 6**: Attempt vulnerability chaining. Try to achieve maximum impact (RCE, full account takeover).<br>**Day 7**: Write comprehensive penetration test report (20+ pages). Include: Executive summary, methodology, findings, remediation.|• Mutillidae II / WebGoat 8<br>• Full testing toolkit<br>• Report template<br>• Time tracking|Comprehensive assessment completed. Professional penetration test report written (20+ pages).|Demonstrate end-to-end capability|
|**Week 2: Certification & Validation**|**Day 1**: Research entry-level security certifications: eWPT, OSCP, OSWA, Burp Suite Certified Practitioner.<br>**Day 2**: Complete free certification prep: PortSwigger's "Burp Suite Certified Practitioner" exam prep.<br>**Day 3**: Take practice exams. Identify weak areas. Focus review on weak areas.<br>**Day 4**: If budget allows, schedule certification exam (eWPT recommended for AppSec).<br>**Day 5**: If no cert budget, complete all remaining PortSwigger labs (aim for 100% completion).<br>**Day 6**: Complete TryHackMe "Jr Penetration Tester" path or similar comprehensive learning path.<br>**Day 7**: Document all completions in portfolio. Add certificates, lab completion badges, statistics.|• PortSwigger certification<br>• eWPT (eLearnSecurity)<br>• TryHackMe paths<br>• Portfolio documentation|Completed certification or equivalent lab path. All achievements documented.|Validation for resume credibility|
|**Week 3: Job Applications & Networking**|**Day 1**: Create target company list (20-30 companies). Research their tech stack, products, security maturity.<br>**Day 2**: Apply to 5 AppSec positions. Customize resume/cover letter for each. Mention internal testing experience.<br>**Day 3**: Reach out to 5 AppSec professionals on LinkedIn. Ask for informational interviews (15-min calls).<br>**Day 4**: Apply to 5 more positions. Include portfolio link in applications.<br>**Day 5**: Participate in security community. Answer questions on r/AskNetsec, Stack Overflow, security forums.<br>**Day 6**: Attend virtual security conference/meetup (OWASP chapter, BSides, local meetup).<br>**Day 7**: Follow up on applications. Send thank-you notes to informational interview contacts.|• Job boards (LinkedIn, Indeed, AngelList)<br>• Networking tools<br>• Virtual conferences<br>• Application tracker|Applied to 10+ positions. Networked with 5+ professionals. Attended 1+ security event.|Active job hunting begins|
|**Week 4: Final Preparations & Continuous Improvement**|**Day 1**: Mock interview practice. Use Pramp or find interview partner. Practice technical explanations.<br>**Day 2**: Review all Month 1-11 notes. Create "quick reference" guide of key concepts.<br>**Day 3**: Set up continuous practice routine: 1 PortSwigger lab daily, 1 bug bounty hour weekly.<br>**Day 4**: SIMULATION: Perform final internal assessment at work. Demonstrate value to employer.<br>**Day 5**: Write "12-Month Retrospective" blog post. Share lessons learned, resources, advice for others.<br>**Day 6**: Create "Month 13+ Learning Plan". Identify next skills: Advanced mobile, thick client, blockchain, etc.<br>**Day 7**: FINAL DELIVERABLE: Complete portfolio review. Ensure all projects documented. Share portfolio publicly.|• Mock interview platforms<br>• All previous resources<br>• Blog platform<br>• Portfolio platform|Portfolio complete and public. Continuous learning plan created. Final internal assessment completed.|Transition to continuous learning mode|

**Month 12 Completion Criteria**:  
✅ Written professional penetration test report (20+ pages)  
✅ Completed certification or equivalent lab completion  
✅ Applied to 10+ AppSec positions  
✅ Portfolio published and comprehensive

---

## 📋 ANTI-PARALYSIS SYSTEM

### Default Tasks by Motivation Level

|Motivation Level|Default Task (No Decision Required)|Duration|
|---|---|---|
|**High**|Continue current week's plan|90 min|
|**Medium**|Complete 1 PortSwigger lab from current month's topic|60 min|
|**Low**|Open Burp Suite, proxy any website, observe traffic for insights|30 min|
|**Very Low**|Read 1 HackerOne disclosed report, take notes|20 min|

### Stuck Protocol

**If stuck on a challenge for 30+ minutes:**

1. Read the official solution/walkthrough
2. Reproduce the solution step-by-step
3. Close the solution
4. Attempt the challenge again from scratch
5. If still stuck, move to next challenge, return next day

**If stuck on a concept:**

1. Switch resources: PortSwigger → OWASP → YouTube → Blog posts
2. Switch learning mode: Reading → Watching → Hands-on practice
3. Post specific question on r/AskNetsec with what you've tried
4. If unresolved after 3 days, skip and add to "revisit" list

### Resource Priority Hierarchy

**When choosing between resources, follow this order:**

1. **PortSwigger Academy Labs** (highest quality, structured)
2. **OWASP Projects** (authoritative, industry-standard)
3. **Vulnerable Applications** (hands-on practice)
4. **Your Own Code/Apps** (highest relevance)
5. **Blog Posts/YouTube** (supplement, not primary)
6. **Courses/Certifications** (after free resources exhausted)

### Preventing Tutorial Hell

**Rules to avoid over-consumption:**

- ❌ Reading 3+ articles on same topic without practicing
- ❌ Watching videos without replicating steps
- ❌ Collecting bookmarks without using them within 7 days
- ✅ RULE: For every 30 minutes of reading/watching, do 60 minutes of hands-on practice
- ✅ RULE: If you can't explain it by typing it out, you don't understand it yet

---

## 🎓 COMPLETION CHECKLIST

After 12 months, you should have:

### Technical Capabilities

- [ ] Exploited 100+ vulnerabilities across OWASP Top 10
- [ ] Tested 10+ different applications independently
- [ ] Written 30+ professional vulnerability reports
- [ ] Reviewed code in 3+ programming languages
- [ ] Integrated security tools into CI/CD pipeline
- [ ] Performed mobile application security testing
- [ ] Conducted cloud security assessment

### Portfolio Deliverables

- [ ] Public security portfolio website
- [ ] 5-10 documented security findings (sanitized)
- [ ] 1-2 blog posts demonstrating expertise
- [ ] GitHub with security tools/scripts
- [ ] Professional penetration test report (20+ pages)
- [ ] Resume highlighting 12-month journey

### Professional Development

- [ ] Active in security community (forums, Discord, Slack)
- [ ] Completed 1+ security certification OR 100+ PortSwigger labs
- [ ] Networked with 5+ security professionals
- [ ] Applied to 10+ AppSec positions
- [ ] Internal security testing experience documented

### Knowledge Validation

- [ ] Can explain OWASP Top 10 to non-technical person
- [ ] Can design secure authentication system
- [ ] Can review pull request for security issues
- [ ] Can build basic security automation
- [ ] Can threat model a web application

---

## 📊 MONTHLY PROGRESS TRACKER

|Month|Core Focus|Key Milestone|Completion %|
|---|---|---|---|
|1|Web Fundamentals|First vulnerability exploited|___%|
|2|Injection & Auth|10 reports written|___%|
|3|Client-Side Security|Portfolio started|___%|
|4|Code Review|First PR review|___%|
|5|Access Control|Testing methodology created|___%|
|6|API Security|API playbook written|___%|
|7|Secure SDLC|Security pipeline built|___%|
|8|Cloud Security|Cloud assessment completed|___%|
|9|Advanced Chains|Vulnerability chain exploited|___%|
|10|Mobile Security|Mobile app tested|___%|
|11|Portfolio & Communication|Portfolio published|___%|
|12|Job Ready|10+ applications submitted|___%|

---

## 🚀 NEXT STEPS AFTER MONTH 12

**Continuous Improvement Plan:**

- Daily: 1 PortSwigger lab (15 min)
- Weekly: 2-hour bug bounty session
- Monthly: 1 new blog post or tool development
- Quarterly: Advanced certification (OSCP, OSWE, GWAPT)

**Specialization Paths:**

- **Deep Web AppSec**: Advanced exploitation, research, bug bounty
- **Mobile Security**: MASVS, mobile penetration testing specialization
- **Cloud Security**: Cloud-specific certifications (AWS Security Specialty)
- **Security Engineering**: Tool development, automation, detection engineering
- **AppSec Leadership**: Security champions program, training development

**Your 12-month journey ends. Your AppSec career begins. 🔒**