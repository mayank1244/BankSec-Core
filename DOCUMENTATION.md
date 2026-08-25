# 🏛️ BankSec Core v1.0 — Technical Architecture, Operational Guide & Scope Specification

## 📋 Executive Summary

**BankSec Core** is an enterprise-grade Application Security & Regulatory Assurance Engine built specifically for banking systems, fintech web applications, payment gateways, and Open Banking APIs. 

It evaluates financial web applications against international banking benchmarks including **OAuth2 FAPI 1.0/2.0 (Financial-Grade API)**, **PCI-DSS v4.0**, **OWASP ASVS Level 3**, and **PSD2 RTS (Strong Customer Authentication)**.

---

## 🎯 1. Tool Uses & Value Proposition

### Why BankSec Core is Essential:
1. **Financial-Grade Compliance**: Generic scanners test basic web vulnerabilities. BankSec Core focuses on financial-grade security controls such as token binding (DPoP), anti-replay transaction locking, and strict header transport policies.
2. **Instant Executive & Auditor Visibility**: Translates technical HTTP probes into an interactive **Audit Score (0–100%)** and **Compliance Grade (Grade A+ to F)**.
3. **Actionable Remediation**: Provides copy-pasteable, production-ready code snippets in **Node.js Express**, **Spring Boot Java**, and **Python FastAPI** for every security control.
4. **Zero-Downtime Safe Probing**: Conducts non-destructive Layer 7 probes, making it safe to run against production banking endpoints without causing service outages or triggering IP bans.

### Primary Use Cases:
- **Pre-Audit Readiness Assessment**: Prepare web applications for RBI, SEBI, ISO 27001, and PCI-DSS v4.0 formal security audits.
- **DevSecOps Integration**: Validate security header configurations and transport encryption in CI/CD staging environments before release.
- **Third-Party Fintech API Vetting**: Verify security postures of third-party vendors and Open Banking partners prior to API integration.
- **Red Team / Pentest Reconnaissance**: Perform rapid external surface profiling of banking domains.

---

## 🏗️ 2. System Architecture

BankSec Core utilizes a decoupled, dual-deployment architecture supporting both **Standalone Local Execution (Node.js)** and **Cloud Serverless Deployment (Streamlit Community Cloud)**.

```
+-----------------------------------------------------------------------+
|                       USER INPUT (Target URL)                         |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                 BankSec Ingestion & URL Normalizer                    |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                 Layer 7 Security Probe Engine                         |
|  - TLS 1.3 Transport Check       - HSTS Preload Verification          |
|  - Content Security Policy (CSP) - X-Frame-Options (Clickjacking)     |
|  - X-Content-Type-Options        - CORS Wildcard (*) Detection        |
|  - Server Banner Info Leakage    - Response Latency Analysis          |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                 Audit Engine & Control Mapper                         |
|  - Update 11 Banking Controls (VERIFIED PASS / AUDIT FAIL)            |
|  - Calculate Compliance Score: (Passed / Total) * 100                 |
|  - Assign Compliance Grade: Grade A+ (>=90%), Grade B, Grade F (<70%) |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                 Output, Reporting & Remediation                       |
|  - Interactive Dashboard UI      - Production Remediation Code        |
|  - OWASP & PCI-DSS Mapping       - Raw JSON Compliance Artifact       |
+-----------------------------------------------------------------------+
```

---

## 🔍 3. Scope Specification: What CAN & CANNOT Be Tested

To maintain compliance and safety, BankSec Core defines explicit boundaries between automated external probes and manual/internal penetration testing.

### ✅ What CAN Be Tested (In-Scope Capabilities)

| Category | Security Control / Test | Description |
| :--- | :--- | :--- |
| **Transport Security** | **HTTPS / TLS Enforcement** | Verifies encryption of data in transit across public networks. |
| **Security Headers** | **HSTS Preloading** | Checks for `Strict-Transport-Security` to prevent SSLStrip attacks. |
| **Script Protection** | **Content Security Policy (CSP)** | Inspects CSP headers to mitigate Cross-Site Scripting (XSS) risks. |
| **Clickjacking Protection** | **X-Frame-Options** | Verifies frame embedding permissions (`DENY` / `SAMEORIGIN`). |
| **MIME Sniffing** | **X-Content-Type-Options** | Verifies `nosniff` flag to prevent MIME-type spoofing. |
| **Cross-Domain Access** | **CORS Access Control** | Detects dangerous wildcard `Access-Control-Allow-Origin: *` policies. |
| **Reconnaissance Risk** | **Server Banner Information Leakage** | Identifies server software version exposure in HTTP response headers. |
| **Regulatory Compliance** | **Automated Standard Mapping** | Maps scan findings directly to OWASP ASVS, PCI-DSS v4.0, and FAPI. |

### ❌ What CANNOT Be Tested (Out-of-Scope / Non-Destructive Boundaries)

| Out-of-Scope Capability | Technical Rationale & Safety Boundary |
| :--- | :--- |
| **Deep Business Logic Exploits** | Tests like transferring negative account balances require internal application context and state mutation, which cannot be probed via external HTTP headers. |
| **Authenticated Session Exploitation** | BankSec Core does not store or inject user login credentials, MFA tokens, or session cookies to ensure customer data protection. |
| **SQL Injection & Payload Fuzzing** | Heavy payload fuzzing is intentionally excluded to prevent database corruption, WAF IP blacklisting, or production service downtime. |
| **Network-Layer Port Scans & DDoS** | Layer 3/4 network scans are excluded; testing is strictly limited to Layer 7 HTTP/HTTPS web and API protocols. |

---

## 🔄 4. Step-by-Step Analysis Workflow

```
[1. User Input] ---> [2. Input Normalization] ---> [3. HTTP Probe Execution]
                                                            |
[6. Compliance Report] <--- [5. Audit Score Dial] <--- [4. Control Mapping Engine]
```

### Step 1: User Input Ingestion
The user enters a target domain or endpoint URL (e.g., `https://onlinebanking.utkarsh.bank.in/`).

### Step 2: Input Normalization & Validation
The engine parses the input using `new URL()`, validates protocol presence (`http://` vs `https://`), and extracts target hostname.

### Step 3: HTTP Probe & Response Header Extraction
The scanner issues a non-destructive HTTP GET probe to the target domain. It extracts the raw response headers:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Access-Control-Allow-Origin`
- `Server` / `X-Powered-By`

### Step 4: Banking Control Mapping Engine
Findings are automatically linked to specific banking security controls in the 5 core domains:
- Missing HSTS --> Fails **`API-01`** (Transport Layer Security)
- Missing CSP --> Fails **`AUTH-01`** (Session & Script Integrity)
- Missing X-Frame-Options --> Fails **`AUTH-03`** (UI Anti-Clickjacking)
- Info Leakage Banner --> Fails **`API-02`** (Gateway Recon Protection)

### Step 5: Audit Score Calculation & Grade Assignment
The engine calculates compliance percentage based on control pass/fail states and assigns the financial compliance grade.

### Step 6: Reporting & Remediation Output
The user views the updated dashboard, inspects recommended remediation code, and exports the raw JSON compliance artifact.

---

## 📊 5. Audit Engine & Scoring Methodology

The Audit Engine evaluates financial software readiness using a transparent percentage formula:

$$\text{Audit Compliance Score (\%)} = \left( \frac{\text{Passed Controls}}{\text{Total Controls}} \right) \times 100$$

### Compliance Grade Classification Matrix

| Audit Score Range | Compliance Grade | Financial Assessment & Action Required |
| :--- | :--- | :--- |
| **90% – 100%** | **GRADE A+ (BANKING COMPLIANT)** | **Audit Approved**: Software satisfies FAPI 1.0/2.0, PCI-DSS v4.0, and ASVS Level 3 requirements. Minimal security risks. |
| **70% – 89%** | **GRADE B (MODERATE RISK)** | **Conditional Pass**: Basic transport security is active, but missing secondary controls (e.g., CSP or rate-limiting headers). Remediation required before release. |
| **0% – 69%** | **GRADE F (CRITICAL VULNERABILITIES)** | **Audit Failed**: Critical banking security controls (HTTPS enforcement, HSTS, CORS) are missing. Unfit for production financial operations. |

---

## 🛡️ 6. Core Banking Security Control Matrix

BankSec Core maps vulnerabilities across **5 Core Banking Security Domains**:

| Domain | Control ID | Control Name | Target Regulatory Standard |
| :--- | :--- | :--- | :--- |
| **1. Authentication & Session** | **`AUTH-01`** | Financial-Grade OAuth2 / FAPI DPoP Enforcer | FAPI 1.0 Advanced / ASVS V2.1 Level 3 |
| | **`AUTH-02`** | PSD2 RTS Strong Customer Authentication (SCA) | PSD2 RTS Article 4 / PCI-DSS 8.3 |
| | **`AUTH-03`** | Anti-Clickjacking Frame Embedding Guard | OWASP ASVS V14.4 / PCI-DSS 6.4 |
| **2. Data Protection & Crypto** | **`DATA-01`** | Field-Level Payload Encryption (JWE/AES-256) | PCI-DSS v4.0 Requirement 3.4 |
| | **`DATA-02`** | Financial PII & PAN Data Masking Guard | PCI-DSS v4.0 Requirement 3.3 |
| **3. API & Transport Security** | **`API-01`** | Mandatory TLS 1.3 & Strict HSTS Preloading | OWASP ASVS V9.1 / FAPI 2.0 |
| | **`API-02`** | API Gateway Rate-Limiting & Info Banner Removal | OWASP API Top 10 API4:2023 |
| **4. Transaction Integrity** | **`TXN-01`** | Anti-Replay HMAC Request Signing | FAPI 1.0 / OWASP API Top 10 API8:2023 |
| | **`TXN-02`** | Financial Idempotency Locking Engine | Banking PSD2 Transaction Integrity |
| **5. Audit & Compliance** | **`LOG-01`** | Tamper-Proof Audit Logging & Non-Repudiation | PCI-DSS v4.0 Requirement 10.2 |
| | **`LOG-02`** | Real-Time Fraud & Anomaly Detection Trigger | PCI-DSS Requirement 10.6 |

---

## 🛠️ 7. Installation & Operational Commands

### Running Locally (Node.js):
```bash
# Navigate to project directory
cd D:\crazy_projects\banksec-suite

# Start Node.js backend server
node server.js

# Access in browser
# http://localhost:8085
```

### Running Streamlit App (Python):
```bash
# Install dependencies
pip install -r requirements.txt

# Launch Streamlit app
streamlit run app.py
```

### Public Live Streamlit Deployment:
👉 **[https://banksec-core-4q43jtsstksw55gvvtzcml.streamlit.app/](https://banksec-core-4q43jtsstksw55gvvtzcml.streamlit.app/)**
