# 🛡️ CloudSentinel: Cloud-Based AI Website Security & Threat Detection System

**MCA Capstone Project & Academic SOC Prototype**  
*Built with Python, Streamlit, Scikit-Learn, Pandas, SQLite, and AWS S3*

---

## 📌 1. Project Overview & Primary Workflow

**CloudSentinel** is a cloud-based AI website security and threat detection prototype designed for real-world website and domain evaluation. The application eliminates manual security-event entry and fake attack simulations; instead, the **main operational workflow begins with real public website checks**.

### Core Architecture & Objectives:
1. **Real-Website-Based Threat Detection (Primary Workflow):** The user enters a public website URL or domain (e.g., `https://example.com`) and clicks **Check Website** to execute safe, bounded, read-only security checks.
2. **Defensive Website Forensics:** Inspects HTTPS reachability, TLS/SSL certificate lifecycle (validity, days until expiration, issuing CA, cipher suite), and audits 6 key defensive HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
3. **VirusTotal API v3 Threat Intelligence:** Integrates VirusTotal API v3 using an API key stored in Streamlit secrets or environment variables. Retrieves existing analysis reports first via base64url encoded URL identifiers; if a URL is not observed and fresh scanning is permitted, requests a scan and retrieves results via the returned analysis ID. Respects API quotas (4 req/min) and never fabricates or invents results.
4. **Transparent Three-Tier Assessment Results:** Classifies each target into exactly one of three clear results:
   - 🚨 **`Potentially Malicious`**
   - ✅ **`No Threat Detected by Available Sources`**
   - ⚠️ **`Unable to Determine`**
   Accompanied by structured, human-readable evidence citing TLS findings, header audit scores, and threat engine flags.
5. **SQLite Persistence & Alert Generation:** Persists each website assessment, timestamp, findings, source, and alert status into SQLite (`website_assessments`). High-severity detections automatically trigger an incident alert with status **`NEW`**.
6. **Five ML Classifiers Comparative Suite (Presented Separately):** Compares five scikit-learn models (Decision Tree, Random Forest, Logistic Regression, Support Vector Machine, and Gradient Boosting) trained on a real, labeled cybersecurity dataset.
7. **Scientific & Architectural Separation (Requirement 7):** A simple passive HTTP request to a public website **cannot** capture internal server telemetry (e.g. database exfiltration bytes, failed password attempts). Therefore, the 5 ML models are benchmarked separately on labeled host telemetry, while website assessments rely on genuine threat reputation and configuration checks.
8. **Strict Server-Side Request Forgery (SSRF) Defense:** Rejects private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), local loopback (`127.0.0.1`, `localhost`, `::1`), link-local autoconfiguration (`169.254.0.0/16`), and cloud instance metadata (`169.254.169.254`). Re-verifies IP safety on all redirect hops.
9. **Incident Alert Lifecycle Management:** Security Analysts and Administrators triage alerts through formal states: **`NEW` ➔ `INVESTIGATING` ➔ `RESOLVED`**.
10. **AWS S3 Archival & Local Simulation Fallback:** Archives website assessments and executive reports to Amazon S3, falling back smoothly to `data/s3_local_simulation/` when AWS credentials or buckets are absent.

---

## 👥 2. Demonstration Roles & Quick Access

CloudSentinel provides role-based access control with pre-configured demonstration accounts:

| Role | Username | Password | Purpose & Demonstration Workflow |
|---|---|---|---|
| **User / Demonstrator** | `demo` | `demo123` | Enters public website URLs for safe threat inspection, tests SSRF protection against loopback/cloud-metadata, and inspects results. |
| **Security Analyst** | `analyst` | `analyst123` | Conducts deep website TLS and headers audits, reviews VirusTotal reputation, and investigates incident alerts. |
| **Administrator / Alert Reviewer** | `admin` | `admin123` | Manages alerts (`NEW` ➔ `INVESTIGATING` ➔ `RESOLVED`), oversees offline ML model benchmarks, and reviews audit logs. |

> **💡 1-Click Quick Demo Switcher:** On the main dashboard (`app.py`), a quick-switcher allows evaluators to instantly switch roles without re-typing credentials.

---

## 🌐 3. Website Threat Checker & SSRF Defense

Located at `pages/1_Website_Threat_Checker.py`, this module conducts passive, read-only security checks:

### Inspections Performed:
1. **TLS/SSL Certificate Verification:**
   - Validates HTTPS connectivity, certificate subject, issuing Certificate Authority (CA), valid date ranges, and days remaining until expiration.
2. **Defensive HTTP Security Headers Audit:**
   - Checks presence and configuration of 6 key defensive headers:
     - `Strict-Transport-Security` (HSTS)
     - `Content-Security-Policy` (CSP)
     - `X-Frame-Options` (Clickjacking defense)
     - `X-Content-Type-Options` (MIME sniffing prevention)
     - `Referrer-Policy` (Data leakage control)
     - `Permissions-Policy` (Hardware API restriction)
3. **Third-Party Reputation Inspection (VirusTotal v3):**
   - Retrieves existing analysis reports first via base64url encoded URL identifier (`GET /api/v3/urls/{id}`).
   - Submits fresh URL analysis if unobserved (`POST /api/v3/urls`) and queries returned analysis ID (`GET /api/v3/analyses/{id}`).
   - Queries domain reputation endpoint (`GET /api/v3/domains/{domain}`).
   - Gracefully handles API rate limits (HTTP 429) and missing API keys without inventing results.
4. **Three Clear Assessment Outcomes:**
   - **`Potentially Malicious`:** VirusTotal flagged malicious/suspicious engines, or severe cryptographic risk (expired/invalid TLS).
   - **`No Threat Detected by Available Sources`:** HTTPS verified, valid TLS certificate, 0 malicious detections across security engines.
   - **`Unable to Determine`:** Target blocked by SSRF defense, host unreachable, connection timed out, or DNS resolution failed.

### 🛡️ SSRF & DNS-Rebinding Protections:
- **Loopback Blocking:** Rejects `127.0.0.1`, `localhost`, `::1`.
- **Private RFC 1918 Blocking:** Rejects `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Cloud Metadata Blocking:** Rejects `169.254.169.254` (AWS/Azure/GCP instance metadata endpoint).
- **DNS Rebinding Protection:** Resolves domain to IP *before* connecting and verifies the IP belongs to a globally routable public address space.
- **Safe Bounded Redirects:** Sets `allow_redirects=False` and re-verifies SSRF safety on each hop before following.

---

## 🧠 4. Five Machine Learning Models Benchmark Suite

Located at `pages/2_Model_Comparison.py`, this module evaluates five scikit-learn models on real, labeled cybersecurity telemetry:

### The 5 Algorithms Compared:
1. **Decision Tree Classifier:** Transparent, tree-structured decision logic using orthogonal feature splits (`max_depth=6`).
2. **Random Forest Classifier (Selected Champion):** Ensemble bagging method combining 100 decorrelated decision trees with bootstrap aggregation.
3. **Logistic Regression:** Linear probabilistic baseline with $L_2$ regularization. Produces smooth calibrated probabilities via the sigmoid function.
4. **Support Vector Machine (SVM):** Radial Basis Function (RBF) kernel with `CalibratedClassifierCV` to provide well-calibrated posterior probabilities.
5. **Gradient Boosting Classifier:** Sequential boosting ensemble that minimizes pseudo-residual loss across successive weak learners.
6. **Isolation Forest (Companion Unsupervised Model):** Sub-linear space partitioning anomaly detector that isolates zero-day statistical outliers.

### Benchmark Evaluation Results (Real Test Split):
| Model | Algorithm | Accuracy | Precision | Threat Recall | Macro F1 | ROC-AUC | Status |
|---|---|---|---|---|---|---|---|
| **Random Forest** | `RandomForestClassifier` | **99.60%** | **98.89%** | **100.00%** | **99.44%** | **99.98%** | 🏆 **Champion** |
| **Gradient Boosting** | `GradientBoostingClassifier` | 99.60% | 98.89% | 100.00% | 99.44% | 99.95% | Candidate |
| **Support Vector Machine** | `CalibratedClassifierCV(SVC)` | 99.60% | 100.00% | 98.88% | 99.44% | 99.88% | Candidate |
| **Logistic Regression** | `LogisticRegression` | 99.60% | 100.00% | 98.88% | 99.44% | 99.91% | Baseline |
| **Decision Tree** | `DecisionTreeClassifier` | 97.60% | 97.70% | 95.51% | 96.59% | 97.08% | Candidate |

> **⚖️ Architectural Note (Requirement 7):**  
> These models are trained on internal telemetry (e.g. failed login attempts, request velocity, data transfer volume, privilege level). A passive HTTP request to an external website does **not** provide internal telemetry. Therefore, CloudSentinel presents the ML comparison separately as an academic benchmark, while using VirusTotal and TLS/headers for website assessments.

---

## 🚨 5. Security Logs & Alert Management Lifecycle

Located at `pages/3_Security_Logs.py`:
- **Real Website Assessments Repository:** Filter by assessment result (`Potentially Malicious`, `No Threat Detected by Available Sources`, `Unable to Determine`), alert status (`NEW`, `INVESTIGATING`, `RESOLVED`), and text search.
- **Incident Alert Triage:** Transition alerts through formal states (**`NEW` ➔ `INVESTIGATING` ➔ `RESOLVED`**) with reviewer assignment, resolution notes, and chronological audit history.
- **Cloud Archival:** Export assessment records to CSV and Amazon S3 with one click.

---

## ☁️ 6. AWS S3 Cloud Integration & Local Simulation Mode

### Configuration:
Set your credentials in `.env`:
```env
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-cloudsentinel-bucket-name
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### Transparent Local Simulation Fallback:
If AWS credentials are missing or the bucket does not exist, CloudSentinel automatically saves archives to `data/s3_local_simulation/` while logging an informative SOC notice. No crashes or blocking errors occur.

---

## 📁 7. Project File Structure

```
CloudSentinel/
│
├── app.py                         # SOC Overview Dashboard, Quick Scan Launcher & Role Switcher
├── auth.py                        # Authentication & PBKDF2/Bcrypt password hashing
├── aws_s3.py                      # AWS S3 uploader with Local Simulation Mode fallback
├── ui_helpers.py                  # Streamlit cybersecurity theme, badges & Plotly layouts
├── website_checker.py             # Website Threat Checker with SSRF defenses, TLS forensics & VirusTotal v3
├── requirements.txt               # Pinned Python package dependencies
├── README.md                      # System documentation & Viva defense guide
│
├── database/                      # Database Layer
│   ├── database.py                # SQLite schema, WAL mode, website_assessments, alerts lifecycle
│   └── security.db                # SQLite database (auto-created on startup)
│
├── ml/                            # Machine Learning & Benchmark Suite
│   ├── preprocess.py              # Standardized features, pipeline builder & metadata
│   ├── train_and_compare.py       # 5-model benchmark suite with 5-fold cross-validation
│   ├── predict.py                 # Active model inference, calibrated probability & risk scoring
│   ├── train_model.py             # Standalone model training runner
│   └── train_anomaly.py           # Isolation Forest anomaly training runner
│
├── data/                          # Telemetry Datasets & Local S3 Storage
│   ├── security_logs.csv          # Base telemetry seed data
│   ├── security_logs_benchmark.csv# Realistic 1,000-event stratified benchmark dataset
│   └── s3_local_simulation/       # Local fallback directory for simulated cloud exports
│
├── models/                        # Serialized ML Model Artifacts
│   ├── threat_model.pkl           # Active Supervised Champion Pipeline (Random Forest)
│   ├── anomaly_model.pkl          # Active Anomaly Detection Pipeline (Isolation Forest)
│   └── benchmarks/                # Serialized candidate pipelines from 5-model comparison
│
├── pages/                         # Streamlit Multi-Page Operations (5 Modules)
│   ├── 1_Website_Threat_Checker.py# Safe URL threat checker, SSRF defense, TLS inspection & VirusTotal
│   ├── 2_Model_Comparison.py      # 5-Model comparative benchmark table, charts & viva notes
│   ├── 3_Security_Logs.py         # Website assessments repository & Alert triage (NEW->INV->RESOLVED)
│   ├── 4_Reports.py               # Executive reports, security headers compliance & S3 export
│   └── 5_Admin_Management.py      # User administration, role management & audit registry
│
└── tests/                         # Comprehensive Automated Unit Tests (31/31 Passing)
    ├── test_auth.py               # Role authentication & password hashing tests
    ├── test_database.py           # SQLite operations, website_assessments & alert history tests
    ├── test_pipeline.py           # Feature engineering & risk calculation tests
    ├── test_five_models.py        # 5 scikit-learn models & benchmark validation tests
    ├── test_website_checker.py    # SSRF protection, loopback blocking, TLS & VirusTotal tests
    ├── test_alerts.py             # Alert lifecycle status transition tests
    └── test_aws_s3.py             # S3 upload & Local Simulation Mode tests
```

---

## ⚡ 8. Step-by-Step PowerShell Run Commands

### 1. Open PowerShell & Navigate to Project:
```powershell
cd "C:\Users\AdmiN\Downloads\New folder"
```

### 2. Activate Virtual Environment:
```powershell
& "C:\Users\AdmiN\Downloads\CloudSentinel\venv\Scripts\Activate.ps1"
```

### 3. Run the Automated Unit Test Suite (31 Tests):
```powershell
& "C:\Users\AdmiN\Downloads\CloudSentinel\venv\Scripts\python.exe" -m unittest discover -s tests
```
*Expected Result: `Ran 31 tests in ... OK`*

### 4. Launch the Streamlit Dashboard:
```powershell
& "C:\Users\AdmiN\Downloads\CloudSentinel\venv\Scripts\streamlit.exe" run app.py
```
Open your browser at: **`http://localhost:8501`**

#### Demonstration Login Credentials:
- **User / Demonstrator:** `demo` / `demo123`
- **Security Analyst:** `analyst` / `analyst123`
- **Administrator / Alert Reviewer:** `admin` / `admin123`

---

## 🎓 9. Academic Viva Defense Questions & Answers

### Q1: Why does CloudSentinel evaluate public websites using passive checks rather than running ML models on HTTP requests?
> **Answer:** Machine learning models for threat classification are trained on internal telemetry features (failed login attempts, request velocity, database exfiltration bytes, targeted privilege level). A simple HTTP GET request to an external website cannot observe the internal operations of that server. Claiming to detect active server intrusions from a basic HTTP request is technically inaccurate. Therefore, CloudSentinel evaluates public websites using passive cryptographic audits (TLS validity, cipher suites), defensive HTTP headers, and verified threat intelligence (VirusTotal API v3), while benchmarking the 5 ML models separately on genuine telemetry logs.

### Q2: How does CloudSentinel protect against Server-Side Request Forgery (SSRF)?
> **Answer:** In `website_checker.py`, the target hostname is resolved to IP addresses *before* making any network connections. The resolved IPs are checked against Python's `ipaddress` library to reject loopback (`127.0.0.0/8`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata endpoints (`169.254.169.254`). Furthermore, automatic redirects are disabled (`allow_redirects=False`) and redirect locations are validated hop-by-hop to prevent DNS rebinding attacks.

### Q3: How is VirusTotal API v3 integrated without exceeding free tier quotas?
> **Answer:** The system retrieves existing URL reports first (`GET /api/v3/urls/{id}`) using a base64url encoded URL identifier. If an existing report is found, no new scan is initiated, conserving API credits. If unobserved and a fresh scan is permitted, it submits the URL (`POST /api/v3/urls`) and checks the returned analysis ID. The system handles HTTP 429 (rate limit exceeded) gracefully and never invents or fabricates results if an API key is unconfigured.

### Q4: Why did Random Forest outperform a single Decision Tree on the benchmark dataset?
> **Answer:** A single Decision Tree is prone to high variance and overfits to training outliers. Random Forest uses bootstrap aggregation (bagging) and random feature sub-spacing across 100 decorrelated trees. By averaging predictions, variance is reduced dramatically while retaining non-linear interaction capture, achieving 100% Threat Recall and 99.44% Macro-F1 on held-out test data.
