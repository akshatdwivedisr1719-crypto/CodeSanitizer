import { ProjectFileInfo } from '../types';

export const PROJECT_FILES_METADATA: ProjectFileInfo[] = [
  {
    path: 'app.py',
    title: 'Streamlit Web Dashboard',
    role: 'User Interface & Frontend Presentation',
    description: 'Main Streamlit application implementing the cybersecurity dashboard, metric scorecards, package verification table, expandable vulnerability inspect panels, before/after secure diffs, and artifact downloads.',
    language: 'python',
  },
  {
    path: 'analyzer.py',
    title: 'AST Code Analyzer',
    role: 'Core Security & Static Analysis Engine',
    description: 'Parses Python code into an Abstract Syntax Tree using Python\'s native ast.parse(). Traverses nodes via CodeSanitizerASTVisitor to detect dangerous functions (eval, exec, compile), system command injection, hardcoded secrets, and SQL injections without ever executing untrusted user code.',
    language: 'python',
  },
  {
    path: 'package_checker.py',
    title: 'PyPI Package Verifier',
    role: 'Supply Chain & Package Hallucination Auditor',
    description: 'Audits imported third-party packages against the live PyPI JSON API using asynchronous httpx requests. Accurately identifies Python standard library modules and flags non-existent hallucinated packages that expose projects to dependency squatting attacks.',
    language: 'python',
  },
  {
    path: 'rules.py',
    title: 'Security Rules & Risk Engine',
    role: 'Ruleset Definitions & Deterministic Scoring',
    description: 'Defines the VulnerabilityFinding data structure, severity categories (CRITICAL, HIGH, MEDIUM, LOW, SAFE), and the deterministic scoring mathematical formula (100 base score with weighted deductions).',
    language: 'python',
  },
  {
    path: 'report.py',
    title: 'Report & Artifact Generator',
    role: 'Audit Export & Remediation Generator',
    description: 'Produces professional Markdown security reports, structured DevSecOps JSON outputs, and automatically generates sanitized .env.example files with detected secret keys without leaking raw credentials.',
    language: 'python',
  },
  {
    path: 'requirements.txt',
    title: 'Dependencies Manifest',
    role: 'Package Requirements',
    description: 'Declares minimal, lightweight dependencies (streamlit>=1.30.0 and httpx>=0.25.0) ensuring the scanner runs instantly in any Python 3.10+ environment.',
    language: 'text',
  },
  {
    path: 'README.md',
    title: 'Project Documentation & Hackathon Pitch',
    role: 'Documentation & Demo Script',
    description: 'Complete documentation covering the AI code generation hallucination problem, architecture diagram, 60-90 second live demo script, rule reference table, and future roadmap.',
    language: 'markdown',
  },
  {
    path: 'test_code/vulnerable.py',
    title: 'Vulnerable Test Code',
    role: 'Demo Test Case (Insecure)',
    description: 'Intentionally vulnerable Python sample featuring AI-hallucinated packages (hallucinated_ai_crypto_guard), hardcoded API keys, SQL injections, eval(), exec(), and os.system() command injection for the hackathon demo.',
    language: 'python',
  },
  {
    path: 'test_code/safe.py',
    title: 'Hardened Reference Code',
    role: 'Demo Test Case (Secure)',
    description: 'Hardened Python reference implementation showing secure remediations: os.getenv() for credentials, parameterized SQL queries, ast.literal_eval(), and subprocess.run(shell=False). Receives a 100/100 score.',
    language: 'python',
  },
];
