# 🏦 BankSec Core
### Open Banking & Financial Security Assurance Engine

[![Security Level](https://img.shields.io/badge/Security_Level-OWASP_ASVS_L3-emerald.svg)](https://owasp.org/www-project-application-security-verification-standard/)
[![Compliance](https://img.shields.io/badge/Compliance-PCI--DSS_v4.0_%7C_FAPI_1.0-blue.svg)](https://openid.net/wg/fapi/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**BankSec Core** is a security assurance platform, real-time API vulnerability scanner, compliance auditor, and remediation engine specifically engineered for banking, fintech, and payment applications.

---

## 🌟 Key Features

1. **📡 Live Real-Time API & Web Scanner**
   * Real-time HTTP/HTTPS protocol vulnerability probes.
   * Security headers verification (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`).
   * Wildcard CORS (`Access-Control-Allow-Origin: *`) exposure detection.
   * Server software banner disclosure leaks (`Server`, `X-Powered-By`).

2. **📊 Automated Interactive Audit Sync**
   * Automatically maps live scan findings to 11 specialized banking security controls across 5 core domains.
   * Dynamically calculates **Risk Index Gauge (0–100%)** and **Compliance Rating (Grade A+ to Grade F)**.
   * Read-only audit mode prevents manual score tampering.

3. **🛡️ OWASP Top 10 & ZAP Alignment**
   * Direct 1-to-1 mapping with **OWASP Top 10 (2021)** and **OWASP API Top 10 (2023)** vulnerability categories.
   * Aligned with **OWASP ASVS Level 3** (Financial-Grade Application Verification).

4. **💻 Production Code Remediation Engine**
   * Copy-paste production security implementations in Node.js (Express), Java (Spring Boot), and Python.
   * Includes OAuth2 FAPI DPoP enforcers, PSD2 Dynamic Linking signers, HMAC-SHA256 request signatures, Redis atomic idempotency locking, and AES-256-GCM envelope encryption.

5. **📄 Exportable Executive Audit Reports**
   * Download structured JSON compliance reports (`BankSec-Audit-Report-<timestamp>.json`) for security auditors and executive management.

---

## 🛠️ Quickstart Guide

### Prerequisites
* [Node.js](https://nodejs.org/) (v16 or higher)

### Installation & Execution

```bash
# Clone the repository
git clone https://github.com/mayank1244/BankSec-Core.git
cd BankSec-Core

# Start the BankSec Core Server
node server.js
```

Open your browser and navigate to:
👉 **`http://localhost:8085`**

---

## 🏗️ Architecture

```
                                +-------------------------------------+
                                |            BankSec Core             |
                                |    (Financial Security Engine)      |
                                +------------------+------------------+
                                                   |
      +--------------------------------------------+--------------------------------------------+
      |                                            |                                            |
+-----v------------------------+      +------------v-------------------+      +-----------------v----------+
|  Live Real-Time Scanner      |      |  Read-Only Audit Evaluator     |      |  Production Code Remediation|
|  (Node.js Backend Engine)    |      |  (ASVS-L3 & Risk Gauge 0-100%) |      |  (Express, Spring Boot, Py) |
+------------------------------+      +--------------------------------+      +----------------------------+
```

---

## 📜 License
Distributed under the **MIT License**.
