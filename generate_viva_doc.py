"""Generate a properly formatted Word document for viva preparation."""
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT

doc = Document()

# -- Styles --
style = doc.styles['Normal']
font = style.font
font.name = 'Calibri'
font.size = Pt(11)

def add_title(text):
    p = doc.add_heading(text, level=0)
    for run in p.runs:
        run.font.size = Pt(24)
        run.font.color.rgb = RGBColor(0, 51, 102)

def add_h1(text):
    p = doc.add_heading(text, level=1)
    for run in p.runs:
        run.font.color.rgb = RGBColor(0, 70, 130)

def add_h2(text):
    p = doc.add_heading(text, level=2)
    for run in p.runs:
        run.font.color.rgb = RGBColor(0, 90, 160)

def add_h3(text):
    doc.add_heading(text, level=3)

def add_para(text):
    doc.add_paragraph(text)

def add_bullet(text, bold_prefix=None):
    p = doc.add_paragraph(style='List Bullet')
    if bold_prefix:
        run = p.add_run(bold_prefix)
        run.bold = True
        p.add_run(f" — {text}")
    else:
        p.add_run(text)

def add_table(headers, rows):
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = 'Light Grid Accent 1'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(10)
    for r_idx, row in enumerate(rows):
        for c_idx, val in enumerate(row):
            cell = table.rows[r_idx + 1].cells[c_idx]
            cell.text = str(val)
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(10)


# ========== COVER ==========
add_title("CloudSentinel — Complete Viva Guide")
doc.add_paragraph("")
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("Cloud-Based AI Website Security & Threat Detection System")
run.font.size = Pt(14)
run.font.color.rgb = RGBColor(80, 80, 80)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("Team Members: 3  |  Framework: Streamlit (Python)  |  Database: SQLite / Amazon RDS")
run.font.size = Pt(11)
run.font.color.rgb = RGBColor(100, 100, 100)
doc.add_page_break()


# ========== PAGE 1: APP ==========
add_h1("Page 1: APP — Home / Login Page")

add_h2("What You See When You Open the Website")
add_bullet("Big title \"CloudSentinel\" with a shield icon")
add_bullet("Tagline: Cloud-Based AI Website Security & Threat Detection System")

add_h2("Three Quick Login Buttons")
add_bullet("Logs in instantly without typing password", "Demonstrator")
add_bullet("Logs in as a security analyst", "Security Analyst")
add_bullet("Logs in with full admin access", "Admin / Reviewer")

add_h2("Sign In Form")
add_bullet("Username or Email field")
add_bullet("Password field")
add_bullet("Default logins: admin/admin123, analyst/analyst123, demo/demo123")

add_h2("Register Form")
add_bullet("Fields: Full Name, Username, Email, Password, Confirm Password")
add_bullet("Public users always get \"Security Analyst\" role (cannot self-register as Admin)")
add_bullet("Passwords hashed with bcrypt (12 rounds) — never stored in plain text")

add_h2("First-Run Setup Wizard")
add_para("If no admin exists in database, a one-time setup wizard appears to create the first administrator account.")

add_h2("Dashboard After Login")
add_h3("5 KPI Metric Cards (real data from database)")
add_bullet("How many websites have been checked", "Total Website Scans")
add_bullet("How many were flagged dangerous", "Potentially Malicious")
add_bullet("How many were clean", "No Threat Detected")
add_bullet("How many could not be assessed", "Unable to Determine")
add_bullet("How many alerts need attention", "Open / New Alerts")

add_h3("5 Navigation Links")
add_bullet("Website Threat Checker")
add_bullet("5 ML Models Benchmark")
add_bullet("Assessments & Alerts")
add_bullet("Executive Reports")
add_bullet("Admin & Audit Logs")

add_h3("Quick Website Scan")
add_para("A text box right on the home page to enter any URL and click \"Check Website\". Shows result instantly.")

add_h3("Recent Assessments Tab")
add_para("Table showing last 8 website scans with columns: ID, Domain, IP, Result, Alert Status, TLS Status, Headers Status, Date.")

add_h2("Sidebar (visible on all pages)")
add_bullet("CloudSentinel logo and name")
add_bullet("Current user info: name, username, role (color-coded badge)")
add_bullet("\"Log Out\" button")

add_h2("4 User Roles & Permissions")
add_table(
    ["Role", "View Dashboard", "Edit Alerts", "Train Models", "Manage Users"],
    [
        ["User / Demonstrator", "Yes", "No", "No", "No"],
        ["Security Analyst", "Yes", "No", "No", "No"],
        ["Alert Reviewer", "Yes", "Yes", "No", "No"],
        ["Administrator", "Yes", "Yes", "Yes", "Yes"],
    ]
)
doc.add_page_break()


# ========== PAGE 2: WEBSITE THREAT CHECKER ==========
add_h1("Page 2: Website Threat Checker")

add_h2("What It Does")
add_para("You enter a public website URL (e.g., https://google.com) and click \"Check Website\". The system performs 3 safe, read-only checks on that website.")

add_h2("Input Section")
add_bullet("Text box to enter URL (e.g., https://example.com or just google.com)")
add_bullet("\"Check Website\" button")
add_bullet("Demo presets: clean site, SSRF blocked localhost, cloud metadata blocked")

add_h2("CHECK 1 — TLS/SSL Certificate Inspection")
add_para("Connects to the website on port 443 (HTTPS) and examines the SSL certificate.")
add_h3("What it shows:")
add_bullet("Is HTTPS available? Yes / No")
add_bullet("Is certificate valid? Yes / No")
add_bullet("Days remaining before expiry (e.g., \"Valid for 245 more days\")")
add_bullet("Subject Common Name (e.g., *.google.com)")
add_bullet("Certificate Authority who issued it (e.g., Google Trust Services)")
add_bullet("TLS protocol version (e.g., TLSv1.3)")
add_h3("How it decides:")
add_bullet("Certificate expired → Potentially Malicious (red)")
add_bullet("Certificate untrusted → Potentially Malicious (red)")
add_bullet("HTTPS not available → Risk flag raised")
add_bullet("Certificate valid → Good sign (green checkmark)")

add_h2("CHECK 2 — HTTP Security Headers Audit")
add_para("Sends a GET request to the website and checks for 6 important defensive security headers:")
add_table(
    ["Header Name", "Importance", "What It Prevents"],
    [
        ["Strict-Transport-Security (HSTS)", "HIGH", "Forces HTTPS, prevents SSL-stripping attacks"],
        ["Content-Security-Policy (CSP)", "HIGH", "Blocks unauthorized scripts, prevents XSS attacks"],
        ["X-Content-Type-Options", "MEDIUM", "Prevents MIME type confusion attacks"],
        ["X-Frame-Options", "MEDIUM", "Prevents clickjacking by blocking iframes"],
        ["Referrer-Policy", "LOW", "Controls URL info sent to other sites"],
        ["Permissions-Policy", "LOW", "Controls access to camera, microphone, geolocation"],
    ]
)
add_para("")
add_h3("What it shows:")
add_bullet("Score: e.g., \"4/6 Recommended Defensive Headers Present\" with progress bar")
add_bullet("List of present headers with values (green checkmarks)")
add_bullet("Missing headers with risk explanations (expandable)")
add_bullet("Server header, response latency, HTTP status code")

add_h2("CHECK 3 — VirusTotal v3 API Reputation")
add_para("Sends the URL to VirusTotal — a database of 70+ antivirus engines worldwide.")
add_h3("How it works:")
add_bullet("Step 1: Check if VirusTotal already has a report for this URL")
add_bullet("Step 2: If no report exists, request a fresh scan")
add_bullet("Step 3: Also check domain reputation separately")
add_h3("What it shows:")
add_bullet("4 metric cards: Malicious count, Suspicious count, Clean/Harmless count, Community Score")
add_bullet("If any engine says malicious → red alert with list of flagging engines")
add_bullet("If all clean → green \"Verified Clean\" message")
add_bullet("If API key not configured → honest message (never fakes results)")

add_h2("How the Final Verdict Is Decided")
add_para("The system combines all 3 checks and gives ONE of these 3 results:")
p = doc.add_paragraph()
run = p.add_run("🚨 \"Potentially Malicious\" — if ANY of these is true:")
run.bold = True
add_bullet("VirusTotal flags malicious by 1+ engine OR suspicious by 2+ engines")
add_bullet("TLS certificate is expired or failed verification")
add_bullet("Both HTTPS and HTTP are completely unreachable (dead/fake domain)")
add_bullet("Domain fails DNS resolution (possible phishing/typosquatting)")
add_bullet("SSRF blocked (tried to scan internal address)")

p = doc.add_paragraph()
run = p.add_run("✅ \"No Threat Detected\" — if ALL of these:")
run.bold = True
add_bullet("TLS connection is valid")
add_bullet("No VirusTotal malicious flags")
add_bullet("Site is reachable")

p = doc.add_paragraph()
run = p.add_run("⚠️ \"Unable to Determine\" — if:")
run.bold = True
add_bullet("URL format is invalid or something went wrong during checks")

add_h2("Result Display")
add_bullet("Big colored banner: green (safe), red (malicious), or gray (undetermined)")
add_bullet("Target URL, domain, timestamp, record ID shown")
add_bullet("Evidence section: bullet list of everything found")
add_bullet("Sources inspected: DNS, TLS, Headers, VirusTotal")

add_h2("4 Forensic Detail Cards")
add_bullet("TLS/SSL certificate details (issuer, expiry, cipher)", "Card 1")
add_bullet("VirusTotal results (engine counts, flagging details)", "Card 2")
add_bullet("HTTP headers audit (present/missing headers, score)", "Card 3")
add_bullet("Network info (resolved IPs, server, latency, status code)", "Card 4")

add_h2("SSRF Protection (Server-Side Request Forgery Defense)")
add_para("Blocks scanning of dangerous internal addresses:")
add_bullet("127.0.0.0/8 (localhost)")
add_bullet("192.168.x.x, 10.x.x.x, 172.16-31.x.x (private networks)")
add_bullet("169.254.169.254 (AWS/GCP/Azure cloud metadata)")
add_bullet(".local and .internal domains")
add_bullet("Max 3 redirect hops, 128KB response size limit")

add_h2("Previous Assessments Tab")
add_para("Shows all past scans stored in SQLite with filters by result type, alert status, and search by domain/IP.")
doc.add_page_break()


# ========== PAGE 3: MODEL COMPARISON ==========
add_h1("Page 3: Model Comparison")

add_h2("What This Page Shows")
add_para("Compares the 3 real website security checks side by side with accuracy and speed charts.")

add_h2("Comparison Table")
add_table(
    ["Check Method", "What It Checks", "Accuracy", "Speed", "Limitation"],
    [
        ["TLS/SSL Certificate", "HTTPS, cert validity, expiry, issuer, TLS version", "~95%", "< 1 sec", "Valid cert ≠ safe content"],
        ["HTTP Security Headers", "6 headers: HSTS, CSP, X-Content-Type, etc.", "~80%", "< 1 sec", "Missing headers ≠ malicious"],
        ["VirusTotal v3 API", "URL & domain reputation, 70+ engines", "~98%", "1–3 sec", "Zero-day sites may not be listed"],
    ]
)

add_h2("Two Bar Charts")
add_bullet("Accuracy comparison (green bars) — VirusTotal highest at 98%")
add_bullet("Speed comparison (orange bars) — TLS and Headers fastest at 0.5 seconds")

add_h2("Best Algorithm: Hybrid Rule-Based Engine")
add_para("TLS + Headers + VirusTotal Combined")
add_para("Weighted verdict: VirusTotal (50%) + TLS (30%) + Headers (20%)")

add_h3("Why this is the best:")
add_bullet("VirusTotal gives highest accuracy by checking 70+ antivirus engines worldwide")
add_bullet("TLS adds cryptographic trust that VirusTotal alone cannot provide")
add_bullet("Headers assess server security configuration quality")
add_bullet("Combined approach covers all angles — no single check is enough alone")
add_bullet("Deterministic — same URL always gives same result (no randomness)")
add_bullet("Fast — total < 3 seconds per scan")
add_bullet("Explainable — can show exactly WHY a site was flagged")

add_h2("Other Algorithms & Why They Are Not Used")
add_table(
    ["Algorithm", "How It Works", "Why Not Used"],
    [
        ["Signature-based", "Matches code against known bad patterns", "Misses new/unknown threats"],
        ["Heuristic rules", "Hand-written if/else rules", "Becomes outdated quickly, many false alarms"],
        ["Sandbox analysis", "Loads page in isolated browser, watches behavior", "Too slow (30+ seconds per page)"],
        ["ML classification", "Trained model predicts safe/malicious", "Needs internal data (login attempts, file access) — can't see from public URL"],
        ["Anomaly detection", "Builds baseline of normal, flags outliers", "Not applicable to one-time URL scans"],
    ]
)
doc.add_page_break()


# ========== PAGE 4: SECURITY LOGS ==========
add_h1("Page 4: Security Logs & Alerts")

add_h2("What This Page Shows")
add_para("All security incident alerts from website scans with triage management.")

add_h2("4 KPI Cards at Top")
add_bullet("Total count of alerts", "Recent Incident Alerts")
add_bullet("Alerts not yet reviewed", "New / Open Alerts")
add_bullet("Alerts being looked into", "Under Investigation")
add_bullet("Alerts that are closed", "Resolved Incidents")

add_h2("Filter Bar")
add_bullet("Status Filter: ALL, NEW, INVESTIGATING, RESOLVED")
add_bullet("Severity Filter: ALL, CRITICAL, HIGH, MEDIUM, LOW")
add_bullet("Search box: search by message, domain, or assignee")
add_bullet("Max Alerts: choose 5, 10, 25, or 50")

add_h2("Export Options")
add_bullet("\"Export CSV\" — downloads all filtered alerts as a spreadsheet")
add_bullet("\"Archive to S3\" — uploads alerts to Amazon S3 cloud storage (or local simulation)")

add_h2("Each Alert Card Shows")
add_bullet("Alert number (e.g., #1, #2)")
add_bullet("Severity badge: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (green)")
add_bullet("Status: NEW (red dot), INVESTIGATING (yellow dot), RESOLVED (green dot)")
add_bullet("Message describing the threat")
add_bullet("Source target (domain or IP)")
add_bullet("Detection source, assigned reviewer, assessment result")

add_h2("Alert Lifecycle (Triage Workflow)")
p = doc.add_paragraph()
run = p.add_run("NEW  →  INVESTIGATING  →  RESOLVED")
run.bold = True
run.font.size = Pt(13)
add_para("For each alert you can: change status, add triage notes (e.g., \"False positive confirmed\"), and click Apply.")

add_h2("Audit Trail")
add_para("Each alert has an expandable history showing who changed what, when, and what notes were added.")
doc.add_page_break()


# ========== PAGE 5: REPORTS ==========
add_h1("Page 5: Executive Reports")

add_h2("5 KPI Cards")
add_para("Total Website Scans | Potentially Malicious | No Threat Detected | Unable to Determine | Open Alerts")

add_h2("Two Visual Charts")
add_bullet("Donut pie chart showing website assessment outcomes (green/red/gray slices)", "Chart 1")
add_bullet("Bar chart showing alert triage status (NEW/INVESTIGATING/RESOLVED in red/yellow/green)", "Chart 2")

add_h2("AI Classification Models Benchmark Table")
add_para("Shows all 5 ML models (Decision Tree, Random Forest, Logistic Regression, SVM, Gradient Boosting) with Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Train Latency. Champion model marked with trophy icon.")

add_h2("Export Options")
add_bullet("\"Download Executive Report (CSV)\" — downloads all data as spreadsheet")
add_bullet("\"Archive to AWS S3\" — uploads report to cloud storage")
doc.add_page_break()


# ========== PAGE 6: ADMIN ==========
add_h1("Page 6: Admin Management")
add_para("Only accessible by Administrator role. Others see \"Access Denied\".")

add_h2("Tab 1 — User RBAC Management")
add_para("RBAC = Role-Based Access Control")
add_bullet("Table of all users: ID, Name, Username, Email, Role, Active Status, Date")
add_bullet("Change any user's role: Analyst, Reviewer, Demonstrator, or Administrator")
add_bullet("Activate or deactivate user accounts")
add_bullet("Delete user accounts")
add_bullet("Safety rule: cannot demote or delete your own admin account")

add_h2("Tab 2 — Audit Logs Explorer")
add_para("Every action in the system is logged here (tamper-evident — cannot be edited or deleted):")
add_bullet("USER_ROLE_CHANGE, USER_STATUS_CHANGE")
add_bullet("ALERT_STATUS_CHANGE, ALERT_ASSIGNMENT")
add_bullet("MODEL_RETRAIN_BENCHMARK")
add_bullet("S3_LOG_ARCHIVE, S3_REPORT_ARCHIVE")
add_para("Each entry shows: ID, Timestamp, Username, Action, Details, IP Address")

add_h2("Tab 3 — Database Backups & S3 Sync")
add_bullet("\"Create Local Database Snapshot\" — copies SQLite database file")
add_bullet("\"Sync Backups to S3\" — uploads backup to Amazon S3 cloud")
add_bullet("Table of existing backup files with filename, size, and date")

add_h2("Tab 4 — Cloud & System Diagnostics")
add_bullet("Database mode (SQLite local or Amazon RDS cloud)", "Database Engine")
add_bullet("S3 configured or simulation mode, bucket name, region", "AWS Cloud Storage")
add_bullet("Threat model and anomaly model active/missing status", "AI Model Persistence")
doc.add_page_break()


# ========== FLOW ==========
add_h1("How Everything Connects (Complete Flow)")
add_para("")
steps = [
    "User opens website → Login page appears",
    "User logs in → Dashboard shows KPIs from database",
    "User enters URL → Website Threat Checker runs TLS + Headers + VirusTotal",
    "Result displayed → Safe (green) or Malicious (red) badge with evidence",
    "Result saved → SQLite database stores the assessment",
    "Alert created → Appears in Security Logs page",
    "Analyst triages → Changes status: NEW → INVESTIGATING → RESOLVED",
    "Reports page → Shows pie charts, bar charts, and benchmarks",
    "Admin page → Manages users, views audit trail, creates backups",
    "S3 archival → Logs, reports, and backups uploaded to AWS cloud",
]
for i, step in enumerate(steps, 1):
    p = doc.add_paragraph()
    run = p.add_run(f"Step {i}: ")
    run.bold = True
    p.add_run(step)

add_h1("Technology Stack")
add_table(
    ["Technology", "Purpose"],
    [
        ["Python 3", "Programming language"],
        ["Streamlit", "Web framework for building the UI"],
        ["SQLite (WAL mode)", "Local database for storing all data"],
        ["Amazon RDS", "Cloud database option (PostgreSQL/MySQL)"],
        ["scikit-learn", "Machine learning library (5 classifiers + Isolation Forest)"],
        ["Plotly Express", "Interactive charts with dark cybersecurity theme"],
        ["AWS S3 + boto3", "Cloud file storage for logs, reports, backups"],
        ["VirusTotal v3 API", "Threat intelligence — 70+ antivirus engines"],
        ["bcrypt", "Password hashing (12 rounds of salting)"],
        ["Custom CSS", "Navy/blue cybersecurity UI theme"],
    ]
)
doc.add_page_break()


# ========== Q&A ==========
add_h1("Quick Viva Q&A (Ready-Made Answers)")

qas = [
    ("What is CloudSentinel?", "A cloud-based AI website security and threat detection system built with Python and Streamlit."),
    ("How does it check if a website is safe?", "Three checks: TLS certificate inspection, HTTP security headers audit, and VirusTotal API reputation lookup across 70+ engines."),
    ("Which is the best algorithm for website scanning?", "Hybrid rule-based engine combining TLS (30%) + Headers (20%) + VirusTotal (50%). It is fast, accurate (~98%), and fully explainable."),
    ("What is SSRF protection?", "Server-Side Request Forgery prevention. Blocks scanning of internal addresses like localhost (127.0.0.1), private IPs (192.168.x.x), and cloud metadata (169.254.169.254)."),
    ("What database do you use?", "SQLite for local development with WAL mode. Supports Amazon RDS (PostgreSQL/MySQL) for cloud deployment."),
    ("How are passwords stored?", "Hashed with bcrypt (12 rounds of salting). Never stored in plain text."),
    ("What is RBAC?", "Role-Based Access Control. 4 roles: Demonstrator, Analyst, Reviewer, Administrator — each with specific permissions."),
    ("What is the alert lifecycle?", "NEW → INVESTIGATING → RESOLVED. Each change is logged in the tamper-evident audit trail."),
    ("What is VirusTotal?", "A free online service that checks URLs and files against 70+ antivirus engines worldwide. We use their v3 API."),
    ("What are the 6 security headers you check?", "HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy."),
    ("What is TLS?", "Transport Layer Security — the encryption protocol that makes HTTPS work. We check if the certificate is valid and not expired."),
    ("What cloud services do you use?", "AWS S3 for file storage, AWS RDS for cloud database (optional), VirusTotal API for threat intelligence."),
    ("What happens if AWS is not configured?", "The system falls back to local simulation mode. S3 saves to a local folder, database uses SQLite. No crashes."),
    ("What are the 5 ML models?", "Decision Tree, Random Forest, Logistic Regression, SVM, Gradient Boosting. They classify internal cybersecurity events (not website scans)."),
    ("Why are ML models and website checks separate?", "Website checks scan public URLs (TLS, headers, VT). ML models analyze internal data (login attempts, file access). A public scan cannot see internal activity — different data needs different methods."),
    ("What is Isolation Forest?", "An unsupervised ML model that detects anomalies in internal security event data by isolating unusual patterns through random cuts."),
]

for q, a in qas:
    p = doc.add_paragraph()
    run = p.add_run(f"Q: {q}")
    run.bold = True
    run.font.color.rgb = RGBColor(0, 70, 130)
    p = doc.add_paragraph()
    run = p.add_run(f"A: {a}")

doc.add_paragraph("")
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("Good luck with your viva! 🎓")
run.bold = True
run.font.size = Pt(16)
run.font.color.rgb = RGBColor(0, 100, 0)

# Save
output_path = r"c:\Users\AdmiN\Downloads\New folder\CloudSentinel_Complete_Viva_Guide.docx"
doc.save(output_path)
print(f"Word document saved to: {output_path}")

