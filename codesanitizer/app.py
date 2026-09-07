"""
app.py - Streamlit Cybersecurity Dashboard for CodeSanitizer
AI-Generated Code & Package Hallucination Auditor.

Run locally:
  streamlit run app.py
"""

import os
import json
import streamlit as st
from analyzer import analyze_python_code
from report import generate_markdown_report, generate_json_report, generate_env_example
from rules import SEVERITY_ICONS, SEVERITY_COLORS

# Streamlit Page Configuration
st.set_page_config(
    page_title="CodeSanitizer | AI Code & Package Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for Cybersecurity Dashboard
st.markdown("""
<style>
    .main-header {
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin-bottom: 0.2rem;
        color: #0f172a;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
    }
    .badge-critical { color: #dc2626; font-weight: 700; }
    .badge-high { color: #ea580c; font-weight: 700; }
    .badge-medium { color: #ca8a04; font-weight: 700; }
    .badge-low { color: #2563eb; font-weight: 700; }
    .badge-safe { color: #16a34a; font-weight: 700; }
    .stCodeBlock { border-radius: 6px; }
</style>
""", unsafe_allow_html=True)


def load_demo_code(filename: str) -> str:
    """Safely loads demo test code from test_code directory."""
    paths_to_try = [
        os.path.join("test_code", filename),
        os.path.join("CodeSanitizer", "test_code", filename),
        os.path.join(os.path.dirname(__file__), "test_code", filename),
    ]
    for p in paths_to_try:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
    return ""


# Sidebar with System Information & Quick Demo Controls
with st.sidebar:
    st.markdown("### ⚙️ Quick Demo Presets")
    st.caption("Designed for 60–90 second hackathon judge presentations.")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🔴 Vulnerable Code", use_container_width=True):
            st.session_state["code_input"] = load_demo_code("vulnerable.py")
            st.session_state["active_tab"] = "Paste"
            st.rerun()

    with col_btn2:
        if st.button("🟢 Safe Code", use_container_width=True):
            st.session_state["code_input"] = load_demo_code("safe.py")
            st.session_state["active_tab"] = "Paste"
            st.rerun()

    st.markdown("---")
    st.markdown("### 🛡️ Detection Modules")
    st.markdown("""
    - **Live PyPI Verification**: PyPI JSON API with async HTTP
    - **AST Structure Analysis**: Python `ast.parse` (Zero Regex-only detection)
    - **Secrets Discovery**: AST Assignment heuristics & redaction
    - **SQL Injection**: AST string interpolation & execute tracing
    - **Dangerous Primitives**: `eval()`, `exec()`, `os.system()`
    - **Safe Execution**: **NEVER** executes submitted code
    """)

    st.markdown("---")
    st.markdown("### 🏆 Hackathon Project")
    st.caption("CodeSanitizer v1.0.0 · Python 3.10+ · Streamlit · PyPI Live API")


# Main Header
st.markdown('<div class="main-header">🛡️ CodeSanitizer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header"><strong>AI-Generated Code & Package Hallucination Auditor</strong><br>'
            '<em>Detect insecure AI-generated code, hallucinated libraries, and critical vulnerabilities before production.</em></div>',
            unsafe_allow_html=True)

# Input Section (Option 1: Paste, Option 2: Upload)
input_mode = st.radio("Choose Input Method:", ["📋 Paste Python Code", "📁 Upload .py File"], horizontal=True)

code_to_analyze = ""

if input_mode == "📋 Paste Python Code":
    default_code = st.session_state.get("code_input", "")
    code_to_analyze = st.text_area(
        "Python Code to Audit:",
        value=default_code,
        height=280,
        placeholder="# Paste AI-generated Python code here...\nimport requests\nAPI_KEY = 'sk-12345'\nquery = 'SELECT * FROM users WHERE id=' + uid",
        help="Paste the Python code you received from an LLM or AI assistant."
    )
else:
    uploaded_file = st.file_uploader("Upload a Python file (.py)", type=["py"])
    if uploaded_file is not None:
        try:
            code_to_analyze = uploaded_file.getvalue().decode("utf-8")
            st.success(f"Loaded file: `{uploaded_file.name}` ({len(code_to_analyze.splitlines())} lines)")
            with st.expander("Preview uploaded file content"):
                st.code(code_to_analyze, language="python")
        except Exception as err:
            st.error(f"Failed to read file: {err}")

col_scan_btn, col_clear_btn = st.columns([2, 8])
with col_scan_btn:
    scan_clicked = st.button("🔍 SCAN CODE", type="primary", use_container_width=True)
with col_clear_btn:
    if st.button("Clear Input"):
        st.session_state["code_input"] = ""
        st.rerun()

st.markdown("---")

# Execution & Report Trigger
if scan_clicked or (code_to_analyze and "last_result" in st.session_state and st.session_state.get("last_code") == code_to_analyze):
    if not code_to_analyze.strip():
        st.warning("⚠️ Please provide Python code to scan by pasting it or uploading a file.")
    else:
        with st.spinner("Parsing AST and verifying packages against live PyPI API..."):
            result = analyze_python_code(code_to_analyze)
            st.session_state["last_result"] = result
            st.session_state["last_code"] = code_to_analyze

        # Error Handling (Syntax error / Parsing error)
        if not result.get("success"):
            if result.get("error_type") == "SYNTAX_ERROR":
                st.error("❌ **Invalid Python Code**")
                st.markdown(f"**Error Details:** `{result.get('message')}`")
                details = result.get("details", {})
                if details.get("text"):
                    st.code(details.get("text"), language="python")
                st.info("💡 Make sure the provided code is syntactically valid Python 3 code before auditing.")
            else:
                st.error(f"❌ Analysis failed: {result.get('message')}")
        else:
            # -------------------------------------------------------------
            # 1. SECURITY OVERVIEW & METRICS
            # -------------------------------------------------------------
            summary = result["summary"]
            score = summary["score"]
            counts = summary["counts"]

            st.subheader("📊 Security Overview")
            
            # Metrics Grid
            col_score, col_crit, col_high, col_med, col_low = st.columns(5)
            with col_score:
                st.metric(
                    label="Security Score",
                    value=f"{score} / 100",
                    delta=summary["badge"],
                    delta_color="normal" if score >= 75 else "inverse"
                )
            with col_crit:
                st.metric(label="🔴 Critical", value=counts.get("CRITICAL", 0))
            with col_high:
                st.metric(label="🟠 High", value=counts.get("HIGH", 0))
            with col_med:
                st.metric(label="🟡 Medium", value=counts.get("MEDIUM", 0))
            with col_low:
                st.metric(label="🔵 Low", value=counts.get("LOW", 0))

            st.caption(f"**Scoring Logic:** {summary['explanation']}")

            st.markdown("---")

            # -------------------------------------------------------------
            # 2. PACKAGE SECURITY & HALLUCINATION SECTION
            # -------------------------------------------------------------
            st.subheader("📦 Package Security & Supply Chain Audit")
            packages = result.get("packages", [])

            if not packages:
                st.info("ℹ️ No external package imports detected in this code.")
            else:
                hallucinated_pkgs = [p for p in packages if p.status == "NOT_FOUND"]
                if hallucinated_pkgs:
                    st.error(
                        f"🚨 **{len(hallucinated_pkgs)} AI-Hallucinated or Non-Existent Package(s) Detected!**\n"
                        "These packages do not exist on PyPI. Installing hallucinated packages exposes systems "
                        "to severe supply chain dependency takeover attacks."
                    )

                pkg_data = []
                for p in packages:
                    if p.status == "VERIFIED":
                        status_str = "✅ Verified on PyPI"
                        extra = f"v{p.version}: {p.summary}" if p.version else (p.summary or "Valid package")
                    elif p.status == "NOT_FOUND":
                        status_str = "❌ NOT FOUND (Hallucinated)"
                        extra = "Package does not exist on PyPI registry!"
                    elif p.status == "STDLIB":
                        status_str = "📘 Python Standard Library"
                        extra = "Built-in Python standard library module"
                    else:
                        status_str = f"⚠️ {p.status}"
                        extra = p.message

                    pkg_data.append({
                        "Package": p.package_name,
                        "Status": status_str,
                        "Lines": ", ".join(str(l) for l in (p.lines or [])),
                        "Details": extra
                    })

                st.table(pkg_data)

            st.markdown("---")

            # -------------------------------------------------------------
            # 3. DETAILED VULNERABILITY FINDINGS
            # -------------------------------------------------------------
            st.subheader(f"🔍 Vulnerability Findings ({len(result['findings'])})")
            findings = result["findings"]

            if not findings:
                st.success("🎉 **Clean Audit!** No dangerous functions, SQL injection, hardcoded secrets, or package hallucinations detected.")
            else:
                # Group findings by severity
                severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                sorted_findings = sorted(
                    findings,
                    key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
                )

                for idx, finding in enumerate(sorted_findings, 1):
                    icon = SEVERITY_ICONS.get(finding.severity, "⚪")
                    expander_label = f"{icon} [{finding.severity}] Line {finding.line}: {finding.title}"
                    
                    with st.expander(expander_label, expanded=(finding.severity in ["CRITICAL", "HIGH"])):
                        st.markdown(f"**Vulnerability Type:** `{finding.rule_id}` | **Line Number:** `{finding.line}`")
                        st.markdown(f"**Triggered Code:**")
                        st.code(finding.code_snippet, language="python")

                        st.markdown(f"**Explanation:** {finding.explanation}")
                        st.markdown(f"**Why It Is Dangerous:** {finding.why}")
                        st.markdown(f"**Recommended Fix:** {finding.recommendation}")

                        if finding.vulnerable_example and finding.recommended_example:
                            col_vuln, col_fix = st.columns(2)
                            with col_vuln:
                                st.markdown("❌ **Vulnerable Pattern:**")
                                st.code(finding.vulnerable_example, language="python")
                            with col_fix:
                                st.markdown("✅ **Secure Replacement:**")
                                st.code(finding.recommended_example, language="python")

            st.markdown("---")

            # -------------------------------------------------------------
            # 4. BONUS FEATURE: ARTIFACT EXPORTS (.env.example & Reports)
            # -------------------------------------------------------------
            st.subheader("📥 Export & Remediation Artifacts")
            
            env_content = generate_env_example(result["findings"])
            md_report = generate_markdown_report(result)
            json_report = generate_json_report(result)

            col_down1, col_down2, col_down3 = st.columns(3)
            with col_down1:
                st.download_button(
                    label="📄 Download Markdown Report",
                    data=md_report,
                    file_name="codesanitizer_report.md",
                    mime="text/markdown",
                    use_container_width=True
                )
            with col_down2:
                st.download_button(
                    label="📊 Download JSON Report",
                    data=json_report,
                    file_name="codesanitizer_report.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_down3:
                st.download_button(
                    label="🔐 Download .env.example",
                    data=env_content,
                    file_name=".env.example",
                    mime="text/plain",
                    use_container_width=True
                )

            with st.expander("👁️ Preview Generated .env.example (Masked Credentials)"):
                st.code(env_content, language="env")
