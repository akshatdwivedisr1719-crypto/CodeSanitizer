# 🛡️ CodeSanitizer

### AI-Generated Code & Package Hallucination Auditor
> **Detect insecure AI-generated code before it reaches production.**

Built for the 4-Hour DevSecOps & AI Security Hackathon.

---

## 📌 Problem Statement

Developers are increasingly generating code using Large Language Models (LLMs). While AI accelerates velocity, it introduces catastrophic security blindspots:

1. **Package Hallucination (Dependency Slopsquatting):** LLMs invent packages that sound legitimate (e.g. `hallucinated_ai_crypto_guard`, `flask_auth_v3`) but **do not exist on PyPI**. Attackers monitor codebases or prompt completions, register these non-existent names on PyPI, and distribute malicious payloads that execute when developers run `pip install`.
2. **Insecure Code Generation:** AI models frequently generate outdated, unparameterized SQL queries (`"SELECT * WHERE id=" + id`), hardcoded testing API keys (`API_KEY = "sk-..."`), and dangerous dynamic execution primitives (`eval()`, `exec()`, `os.system()`).
3. **Regex Inadequacy:** Simple string searches fail to distinguish between safe string mentions and actual structural AST executions.

---

## 💡 The Solution: CodeSanitizer

**CodeSanitizer** is a specialized security auditor that parses Python code structurally using Python's native **Abstract Syntax Tree (`ast`)** engine, extracts all imported packages, and checks them in real-time against the **live PyPI JSON API**.

- 🚫 **Never executes untrusted code** (pure static AST traversal).
- ⚡ **Live PyPI Verification** with asynchronous HTTP requests (`httpx`) and automatic standard library exclusion.
- 🎯 **Pinpoint Accuracy**: Identifies exact line numbers, vulnerable snippets, vulnerability explanations, and provides deterministic **secure replacements**.
- 📊 **Deterministic Security Scoring** (0–100) based on weighted severity levels.
- 🔐 **Remediation Artifact Generation**: Instantly exports sanitized `.env.example` templates and downloadable audit reports (Markdown & JSON).

---

## 🏗️ Architecture & Project Structure

```text
CodeSanitizer/
│
├── app.py                  # Streamlit frontend & interactive cybersecurity dashboard
├── analyzer.py             # AST parsing & visitor engine (never executes submitted code)
├── package_checker.py      # Live PyPI API verifier with async httpx & stdlib filter
├── rules.py                # Security rules, severity weights, and deterministic score engine
├── report.py               # Markdown, JSON, and sanitized .env.example generator
├── requirements.txt        # Minimal dependencies (streamlit, httpx)
├── README.md               # Documentation & 60-90 second presentation script
└── test_code/
    ├── vulnerable.py       # Insecure test sample with hallucinated packages, SQLi, secrets
    └── safe.py             # Hardened reference sample achieving 100/100 score
```

### Execution Flow

```text
[ USER CODE / FILE ]
        │
        ▼
   [ ast.parse() ]  ──(Syntax Check)──> [ Friendly Error on Invalid Python ]
        │
        ├───> [ Extract Imports ] ──> [ Live PyPI API Query ] ──> [ Flag Hallucinations ]
        │
        └───> [ AST NodeVisitor ]
                ├── Dangerous Functions (eval, exec, compile)
                ├── Dangerous System Commands (os.system, subprocess with shell=True)
                ├── Hardcoded Secrets (API_KEY, PASSWORD, TOKEN assignment heuristics)
                └── SQL Injections (concatenation, f-strings, cursor.execute)
        │
        ▼
   [ Deterministic Risk Engine ] ──> Score: 0-100 & Severity Distribution
        │
        ▼
   [ Streamlit Cyber Dashboard ] ──> Visual metrics, before/after diffs, .env generator
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.10 or newer

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Web Dashboard
```bash
streamlit run app.py
```

### 3. Run via CLI (Headless Mode)
```bash
python3 analyzer.py test_code/vulnerable.py
python3 analyzer.py test_code/safe.py
```

---

## ⏱️ 60–90 Second Hackathon Demo Guide

1. **Launch Dashboard**: Open the Streamlit dashboard in your browser.
2. **Load Vulnerable Preset**: Click **"🔴 Vulnerable Code"** in the sidebar (loads `test_code/vulnerable.py`).
3. **Click "🔍 SCAN CODE"**:
   - Notice the **0 / 100 Hazard score** with 2 Critical, 8 High vulnerabilities.
   - **Show Package Table**: Highlights `hallucinated_ai_crypto_guard` and `fake_deep_optimizer_pkg` marked as **❌ NOT FOUND on PyPI**.
   - **Show SQL Injection**: Expand findings to show before/after remediation with parameterized queries.
   - **Show Hardcoded Secrets**: Note how secrets are masked (`sk-l***84`) and an automatic `.env.example` template is ready for download.
   - **Show Dangerous Primitives**: Highlights `eval()` and `os.system()` with safe replacements.
4. **Load Safe Preset**: Click **"🟢 Safe Code"** in the sidebar (loads `test_code/safe.py`).
5. **Click "🔍 SCAN CODE"**:
   - Score resets to **100 / 100 (🟢 SAFE & COMPLIANT)**. All packages verified on PyPI or recognized as Python standard library.

---

## 🛡️ Security Checks & Rule Matrix

| Rule ID | Name | Severity | Penalty | Description |
| :--- | :--- | :---: | :---: | :--- |
| `PACKAGE_HALLUCINATION` | AI Package Hallucination | **HIGH** | -15 | Package absent from PyPI registry. High supply chain takeover risk. |
| `DANGEROUS_FUNC_EVAL` | Dangerous Function `eval()` | **CRITICAL** | -30 | Arbitrary Python expression execution from untrusted input. |
| `DANGEROUS_FUNC_EXEC` | Dangerous Function `exec()` | **CRITICAL** | -30 | Dynamic statement execution leading to Remote Code Execution (RCE). |
| `DANGEROUS_FUNC_COMPILE` | Dynamic `compile()` | **HIGH** | -15 | Bytecode generation from dynamic strings. |
| `DANGEROUS_SYS_OS_SYSTEM`| System Command `os.system()`| **HIGH** | -15 | Unescaped shell execution vulnerable to command injection. |
| `DANGEROUS_SYS_SUBPROCESS`| Subprocess `shell=True` | **HIGH** | -15 | Invokes system shell; enables metacharacter injection. |
| `HARDCODED_SECRET` | Hardcoded Secret/Credential | **HIGH** | -15 | Sensitive credentials in code committed to version control. |
| `SQL_INJECTION_ASSIGNMENT`| Dynamic SQL Query | **HIGH** | -15 | User input concatenated or formatted directly into an SQL string. |
| `SQL_INJECTION_EXECUTE` | SQL Injection in DB Execute | **HIGH** | -15 | Raw interpolated queries passed into `cursor.execute()`. |
| `INSECURE_DESERIALIZATION`| Pickle Deserialization | **HIGH** | -15 | Unpickling untrusted data leads to arbitrary code execution. |

---

## 📈 Transparent Scoring Engine

```text
Base Score: 100 Points
Deductions:
  - CRITICAL:  -30 points each
  - HIGH:      -15 points each
  - MEDIUM:    -8 points each
  - LOW:       -3 points each

Security Score = Max(0, 100 - Total Deductions)
```

---

## 🔮 Future Scope & Roadmap

- **Multi-language Support**: Extend AST parsers to JavaScript/TypeScript (`@babel/parser`) and Go (`go/ast`).
- **NPM & Crates.io Checkers**: Add package verification for Node.js and Rust ecosystems.
- **CI/CD GitHub Action**: Automatic pull request checks blocking hallucinated packages and hardcoded secrets.
- **Automated Pull Request Remediation**: One-click PR creation applying recommended parameterized SQL and `.env` migrations.

---

## 👥 Credits
Created for the **4-Hour DevSecOps & AI Security Hackathon** by the CodeSanitizer Team.
Built with Python 3.10+, Streamlit, Python `ast`, and the PyPI JSON API.
