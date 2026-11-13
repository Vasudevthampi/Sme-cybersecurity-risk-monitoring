# Small and Medium Enterprises (SME) Cybersecurity Risk Monitor

An enterprise-ready, lightweight **Cybersecurity Posture & Risk Monitoring Platform** designed specifically for Small and Medium Enterprises (SMEs). Built with **Java 21 (LTS)** and **Spring Boot 3.3.4**, featuring an embedded zero-configuration **H2 Database** and a responsive modern dashboard (**Thymeleaf + Tailwind CSS + Chart.js**).

---

## 🎯 The SME Cybersecurity Problem

SMEs face an asymmetrical cybersecurity landscape:
1. **Targeted Attacks**: Over 43% of cyberattacks hit small businesses—primarily through **Business Email Compromise (BEC)**, **exposed Remote Desktop (RDP 3389)**, **WannaCry/EternalBlue SMB (445)**, and **unpatched web services**.
2. **Resource Constraints**: SMEs lack dedicated Security Operations Centers (SOCs) or multi-thousand-dollar SIEM licenses (Splunk, Tenable, Qualys).
3. **Complex Compliance**: Insurance providers and clients demand proof of compliance with standards like **NIST CSF 2.0** or **CIS Controls**.

This application solves these challenges by providing automated, non-intrusive auditing, actionable plain-English remediation guides, and instant executive reporting.

---

## 🚀 Key Features

### 1. 🛡️ Executive Posture & Risk Dashboard
- **Cyber Health Score (0 - 100)** and Posture Letter Grade (**A+, A, B, C, D, F**).
- **Threat Vector Risk Distribution Chart**: Network Ports, SSL/TLS, Security Headers, Email Spoofing, and CVE Correlation.
- **NIST CSF Framework Compliance Gauge** (Identify, Protect, Detect, Respond, Recover).
- **High-Priority Security Alerts** & **SME Quick Wins** (&le; 10 mins fix time).

### 2. 🔍 Multi-Vector Automated Security Auditor
- **Port & Service Scanner**: Safely checks 15 critical ports (FTP 21, SSH 22, Telnet 23, SMTP 25, HTTP 80, POP3 110, IMAP 143, HTTPS 443, SMB 445, MSSQL 1433, MySQL 3306, RDP 3389, Postgres 5432, Alt-Web 8080, MongoDB 27017).
- **SSL/TLS Cryptographic Inspector**: Validates X.509 certificate chains, expiration countdown, protocol security (TLS 1.3 vs deprecated SSLv3/TLS 1.0), and CA trust.
- **HTTP Security Headers Auditor**: Checks for `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options`, `Referrer-Policy`, and server version disclosure.
- **Email Spoofing & Phishing Defense (DNS Analyzer)**: Audits live DNS TXT records for SPF (`v=spf1`) and DMARC (`v=DMARC1; p=reject|quarantine|none`) to combat invoice fraud.
- **Vulnerability & CVE Matcher**: Correlates detected software versions against curated CVE records (e.g. OpenSSH regreSSHion, Log4Shell, Apache path traversal, BlueKeep).

### 3. 📋 NIST CSF 2.0 & CIS Controls Self-Assessment
- 13 weighted, practical controls across the 5 NIST CSF functions.
- Interactive status selector (**Implemented**, **Partial**, **Not Implemented**) with instant risk score recalculation.

### 4. 📖 Actionable SME Remediation Playbook
- Plain-English copy-paste recipes for:
  - Adding DMARC & SPF DNS TXT records.
  - Blocking exposed RDP 3389 and SMB 445.
  - Enabling HSTS & CSP in Nginx and Apache.
  - Deploying the 3-2-1 Ransomware-Proof Immutable Backup strategy.

### 5. 📄 Executive Risk Posture Report (Print / PDF)
- Formal assessment report formatted for SME directors, board meetings, and cyber insurance underwriters.
- Built-in `@media print` styling for 1-click **"Print / Save as PDF"**.

---

## 🏗️ Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Language** | Java 21 (LTS) | Modern Java records, concurrency, and pattern matching. |
| **Framework** | Spring Boot 3.3.4 | Rock-solid enterprise standard for MVC and REST. |
| **Persistence** | Spring Data JPA / Hibernate | Clean Object-Relational Mapping. |
| **Database** | H2 Embedded Database | Zero setup required; file-based persistence in `./data/smedb`. |
| **Frontend** | Thymeleaf + Tailwind CSS + Chart.js | Modern, clean dashboard without complex Node.js build pipelines. |
| **Icons** | FontAwesome 6 | Professional security dashboard iconography. |
| **Build Tool** | Apache Maven | Standard dependency and packaging lifecycle. |

---

## 💻 How to Run the Application

### Option A: 1-Click Batch Script (Windows)
Double-click or run:
```cmd
run.bat
```
This automatically sets up `JAVA_HOME` and launches the application on port **8085**.

### Option B: Maven Wrapper (Command Line)
```cmd
mvnw.cmd spring-boot:run
```

### Option C: Run Packaged Executable JAR
```cmd
java -jar target/sme-cyber-risk-monitor-1.0.0.jar
```

---

## 🌐 Application URL Directory

Once started, open your web browser to:

| Page / Tool | URL | Description |
| :--- | :--- | :--- |
| **Dashboard** | `http://localhost:8085/` | Main SME security posture & risk dashboard. |
| **Asset Inventory** | `http://localhost:8085/assets` | Register, manage, and audit digital assets. |
| **NIST CSF Compliance** | `http://localhost:8085/compliance` | Interactive cyber hygiene self-assessment. |
| **Remediation Playbook** | `http://localhost:8085/playbook` | Step-by-step copy-paste fix instructions. |
| **Executive Report** | `http://localhost:8085/report` | Printable executive summary report. |
| **REST API Stats** | `http://localhost:8085/api/v1/stats` | JSON endpoint for programmatic integration. |
| **H2 Database Console** | `http://localhost:8085/h2-console` | JDBC URL: `jdbc:h2:file:./data/smedb`, User: `sa`, Password: (empty). |

---

## 🧪 Automated Testing

Run the automated test suite with:
```cmd
mvnw.cmd test
```
Tests cover:
- Composite risk scoring algorithms and category weightings.
- Criticality multiplier impact on high-priority assets.
- Asset hostname cleaning and URL normalization.
- Letter grade classification logic (A+ to F).