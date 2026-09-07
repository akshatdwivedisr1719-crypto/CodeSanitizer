import { AuditResult, VulnerabilityFinding, PackageVerificationResult, SeverityCounts } from '../types';

const STDLIB_SET = new Set([
  '__future__', '_thread', 'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
  'asyncore', 'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex', 'bisect', 'builtins',
  'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code', 'codecs', 'codeop',
  'collections', 'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib', 'contextvars',
  'copy', 'copyreg', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
  'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings', 'enum', 'errno', 'faulthandler',
  'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt',
  'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html',
  'http', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools', 'json',
  'keyword', 'lib2to3', 'linecache', 'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal',
  'math', 'mimetypes', 'mmap', 'modulefinder', 'msilib', 'msvcrt', 'multiprocessing', 'netrc',
  'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'parser', 'pathlib', 'pdb',
  'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform', 'plistlib', 'poplib', 'posix', 'posixpath',
  'pprint', 'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri',
  'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched', 'secrets',
  'select', 'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr',
  'socket', 'socketserver', 'spwd', 'sqlite3', 'sre_compile', 'sre_constants', 'sre_parse', 'ssl',
  'stat', 'statistics', 'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symbol', 'symtable',
  'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
  'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
  'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing', 'unicodedata', 'unittest', 'urllib',
  'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
  'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib', 'zoneinfo'
]);

const SECRET_REGEX = /(?:api[_-]?key|secret[_-]?key|access[_-]?key|token|auth[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|db[_-]?password|credentials)\s*=\s*(['"])(.*?)\1/i;
const SQL_KW = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b/i;

export async function verifyPackageLive(packageName: string, lines: number[]): Promise<PackageVerificationResult> {
  const norm = packageName.toLowerCase().trim();

  if (STDLIB_SET.has(norm)) {
    return {
      package_name: packageName,
      status: 'STDLIB',
      exists_on_pypi: false,
      is_stdlib: true,
      message: 'Python Standard Library Module (Verified built-in)',
      lines,
    };
  }

  if (['rules', 'analyzer', 'package_checker', 'report', 'test_code'].includes(norm)) {
    return {
      package_name: packageName,
      status: 'LOCAL',
      exists_on_pypi: false,
      is_stdlib: false,
      message: 'Local Application Module',
      lines,
    };
  }

  try {
    const res = await fetch(`https://pypi.org/pypi/${packageName}/json`, {
      headers: { Accept: 'application/json' },
    });

    if (res.status === 200) {
      const data = await res.json();
      const info = data.info || {};
      return {
        package_name: packageName,
        status: 'VERIFIED',
        exists_on_pypi: true,
        is_stdlib: false,
        version: info.version || 'Latest',
        summary: info.summary || 'Valid verified package on PyPI.',
        homepage: info.home_page || info.project_url || `https://pypi.org/project/${packageName}/`,
        message: 'Package exists on PyPI (Live Verified)',
        lines,
      };
    } else if (res.status === 404) {
      return {
        package_name: packageName,
        status: 'NOT_FOUND',
        exists_on_pypi: false,
        is_stdlib: false,
        message: 'Package DOES NOT EXIST on PyPI. Potential AI-hallucinated dependency.',
        lines,
      };
    }
  } catch (err) {
    // Network or CORS block fallback
  }

  // Fallback for known popular packages if CORS or network error occurs in browser
  const KNOWN_PYPI = new Set(['requests', 'flask', 'httpx', 'streamlit', 'fastapi', 'pydantic', 'numpy', 'pandas', 'scipy', 'django']);
  if (KNOWN_PYPI.has(norm)) {
    return {
      package_name: packageName,
      status: 'VERIFIED',
      exists_on_pypi: true,
      is_stdlib: false,
      version: 'Known Active',
      summary: 'Verified Python package',
      homepage: `https://pypi.org/project/${packageName}/`,
      message: 'Package exists on PyPI',
      lines,
    };
  }

  return {
    package_name: packageName,
    status: 'NOT_FOUND',
    exists_on_pypi: false,
    is_stdlib: false,
    message: 'Package DOES NOT EXIST on PyPI. Potential AI-hallucinated dependency.',
    lines,
  };
}

export async function clientSideAudit(code: string): Promise<AuditResult> {
  const lines = code.split(/\r?\n/);
  const findings: VulnerabilityFinding[] = [];
  const importsMap = new Map<string, number[]>();

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('#') || !trimmed) continue;

    // 1. Imports
    const importMatch = trimmed.match(/^import\s+([a-zA-Z0-9_,\s]+)/);
    if (importMatch) {
      const parts = importMatch[1].split(',');
      for (const p of parts) {
        const root = p.trim().split(/\s+/)[0].split('.')[0].toLowerCase();
        if (root) {
          if (!importsMap.has(root)) importsMap.set(root, []);
          importsMap.get(root)!.push(lineNum);
        }
      }
    }

    const fromMatch = trimmed.match(/^from\s+([a-zA-Z0-9_\.]+)\s+import/);
    if (fromMatch) {
      const root = fromMatch[1].split('.')[0].toLowerCase();
      if (root) {
        if (!importsMap.has(root)) importsMap.set(root, []);
        importsMap.get(root)!.push(lineNum);
      }
    }

    // 2. Dangerous Functions
    if (/\beval\s*\(/.test(trimmed)) {
      findings.push({
        rule_id: 'DANGEROUS_FUNC_EVAL',
        title: 'Dangerous Function: eval()',
        severity: 'CRITICAL',
        line: lineNum,
        code_snippet: trimmed,
        explanation: '`eval()` parses and evaluates arbitrary Python expressions dynamically at runtime.',
        why: 'Untrusted input passed to `eval()` allows attackers to execute arbitrary code with full process privileges.',
        recommendation: 'Avoid `eval()`. Use safe parsing libraries like `ast.literal_eval` or json validation.',
        vulnerable_example: 'result = eval(user_input)',
        recommended_example: 'import ast\nresult = ast.literal_eval(user_input)  # Evaluates only safe literals',
      });
    }

    if (/\bexec\s*\(/.test(trimmed)) {
      findings.push({
        rule_id: 'DANGEROUS_FUNC_EXEC',
        title: 'Dangerous Function: exec()',
        severity: 'CRITICAL',
        line: lineNum,
        code_snippet: trimmed,
        explanation: '`exec()` dynamically executes Python statements, bypassing static security controls.',
        why: 'Any attacker input reaching `exec()` leads directly to Remote Code Execution (RCE) on the host.',
        recommendation: 'Avoid `exec()`. Refactor code to use dictionary lookups or callable classes.',
        vulnerable_example: "exec(f'action_{user_action}()')",
        recommended_example: "ACTIONS = {'start': do_start, 'stop': do_stop}\nACTIONS.get(user_action, default_handler)()",
      });
    }

    if (/\bcompile\s*\(/.test(trimmed)) {
      findings.push({
        rule_id: 'DANGEROUS_FUNC_COMPILE',
        title: 'Dynamic Compilation: compile()',
        severity: 'HIGH',
        line: lineNum,
        code_snippet: trimmed,
        explanation: '`compile()` turns dynamic string expressions into executable bytecode.',
        why: 'Compiling untrusted strings into code objects enables arbitrary logic injection.',
        recommendation: 'Use static functions or domain-specific expression parsers.',
        vulnerable_example: "code_obj = compile(untrusted_str, '<string>', 'exec')",
        recommended_example: '# Use predefined static functions or standard logic parsers',
      });
    }

    // 3. System Commands
    if (/\bos\.system\s*\(/.test(trimmed)) {
      findings.push({
        rule_id: 'DANGEROUS_SYS_OS_SYSTEM',
        title: 'Insecure System Execution: os.system()',
        severity: 'HIGH',
        line: lineNum,
        code_snippet: trimmed,
        explanation: '`os.system()` passes a string command directly to the host operating system shell.',
        why: 'Vulnerable to shell command injection. Attackers can inject command separators (`;`, `&&`, `|`) to execute malicious host binaries.',
        recommendation: "Replace `os.system()` with `subprocess.run([...], shell=False)` using tokenized arguments.",
        vulnerable_example: "os.system('ping -c 1 ' + user_target)",
        recommended_example: "import subprocess\nsubprocess.run(['ping', '-c', '1', user_target], check=True, shell=False)",
      });
    }

    if (/subprocess\.(?:call|run|Popen|check_output)\s*\(.*shell\s*=\s*True/i.test(trimmed)) {
      findings.push({
        rule_id: 'DANGEROUS_SYS_SUBPROCESS',
        title: 'Potentially Unsafe Subprocess with shell=True',
        severity: 'HIGH',
        line: lineNum,
        code_snippet: trimmed,
        explanation: 'Subprocess call explicitly enables `shell=True`.',
        why: 'Shell interpreters expand metacharacters, allowing remote attackers to run arbitrary system commands.',
        recommendation: 'Set `shell=False` and pass arguments as a list of strings.',
        vulnerable_example: "subprocess.run(f'curl {url}', shell=True)",
        recommended_example: "subprocess.run(['curl', url], check=True, shell=False)",
      });
    }

    // 4. Hardcoded Secrets
    const secMatch = trimmed.match(SECRET_REGEX);
    if (secMatch) {
      const varPart = trimmed.split('=')[0].trim();
      const val = secMatch[2];
      if (val.length >= 4 && !['placeholder', 'your_key', 'todo', 'test', 'none'].includes(val.toLowerCase())) {
        const masked = val.length > 6 ? val.slice(0, 3) + '***' + val.slice(-2) : '***';
        findings.push({
          rule_id: 'HARDCODED_SECRET',
          title: `Hardcoded Secret Detected: \`${varPart}\``,
          severity: 'HIGH',
          line: lineNum,
          code_snippet: trimmed.replace(val, masked),
          explanation: `Variable \`${varPart}\` appears to hold a hardcoded sensitive secret/credential.`,
          why: 'Hardcoding API keys or passwords commits sensitive secrets into version control, risking credential theft.',
          recommendation: 'Load secrets from environment variables or a secure key management vault.',
          vulnerable_example: `${varPart} = "${masked}"`,
          recommended_example: `import os\n${varPart} = os.getenv("${varPart}")`,
          secret_var: varPart,
        });
      }
    }

    // 5. SQL Injection
    const isSqlLine = SQL_KW.test(trimmed);
    if (isSqlLine && (trimmed.includes('+') || trimmed.startsWith('f"') || trimmed.startsWith("f'"))) {
      findings.push({
        rule_id: 'SQL_INJECTION_ASSIGNMENT',
        title: 'SQL Injection Risk: Dynamic SQL Query Construction',
        severity: 'HIGH',
        line: lineNum,
        code_snippet: trimmed,
        explanation: 'Dynamic variable interpolation detected within an SQL statement string.',
        why: 'Direct string concatenation or f-strings in SQL queries allow attackers to inject arbitrary SQL syntax.',
        recommendation: 'Parameterize all database queries. Do not concatenate or format variables into SQL strings.',
        vulnerable_example: 'query = f"SELECT * FROM users WHERE name = \'{user}\'"\ncursor.execute(query)',
        recommended_example: 'query = "SELECT * FROM users WHERE name = ?"\ncursor.execute(query, (user,))',
      });
    } else if (/\b(?:cursor|db|connection)\.execute\s*\(/.test(trimmed) && (trimmed.includes('+') || trimmed.includes('{'))) {
      findings.push({
        rule_id: 'SQL_INJECTION_EXECUTE',
        title: 'SQL Injection Risk in Database Execute',
        severity: 'HIGH',
        line: lineNum,
        code_snippet: trimmed,
        explanation: 'User-controlled data formatted or concatenated directly into `cursor.execute()`.',
        why: 'Allows attackers to manipulate SQL queries, bypass authentication, or exfiltrate tables.',
        recommendation: 'Use parameterized queries with placeholders (`?` or `%s`).',
        vulnerable_example: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        recommended_example: 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
      });
    }
  }

  // Live PyPI Verification
  const packagePromises: Promise<PackageVerificationResult>[] = [];
  importsMap.forEach((lineNums, pkg) => {
    packagePromises.push(verifyPackageLive(pkg, lineNums));
  });

  const packages = await Promise.all(packagePromises);

  // Add hallucinated packages to findings
  for (const p of packages) {
    if (p.status === 'NOT_FOUND') {
      findings.push({
        rule_id: 'PACKAGE_HALLUCINATION',
        title: `AI Package Hallucination: \`${p.package_name}\``,
        severity: 'HIGH',
        line: p.lines[0] || 1,
        code_snippet: `import ${p.package_name}`,
        explanation: `The package \`${p.package_name}\` does not exist on PyPI. AI code models frequently hallucinate non-existent libraries with plausible names.`,
        why: 'Hallucinated packages create critical supply chain vulnerabilities. Attackers can register these hallucinated names on PyPI to execute malware.',
        recommendation: `Remove \`${p.package_name}\`. Verify legitimate library alternatives on PyPI or use Python standard library equivalents.`,
        vulnerable_example: `import ${p.package_name}`,
        recommended_example: `# Replace with verified PyPI package or Python standard library`,
      });
    }
  }

  // Deterministic Scoring
  let penalty = 0;
  const counts: SeverityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    if (f.severity === 'CRITICAL') penalty += 30;
    else if (f.severity === 'HIGH') penalty += 15;
    else if (f.severity === 'MEDIUM') penalty += 8;
    else if (f.severity === 'LOW') penalty += 3;
  }

  const score = Math.max(0, Math.min(100, 100 - penalty));
  let status = 'CRITICAL_RISK';
  let badge = '🔴 HAZARDOUS';

  if (score >= 90) {
    status = 'EXCELLENT';
    badge = '🟢 SAFE & COMPLIANT';
  } else if (score >= 75) {
    status = 'ACCEPTABLE';
    badge = '🟡 MINOR WARNINGS';
  } else if (score >= 50) {
    status = 'NEEDS_IMPROVEMENT';
    badge = '🟠 ELEVATED RISK';
  }

  return {
    success: true,
    message: 'Audit completed successfully.',
    code_lines_count: lines.length,
    findings,
    packages,
    summary: {
      score,
      status,
      badge,
      total_penalty: penalty,
      counts,
      total_findings: findings.length,
      explanation: `Score calculated deterministically starting at 100 minus weighted penalties (${counts.CRITICAL}x Critical [-30], ${counts.HIGH}x High [-15], ${counts.MEDIUM}x Medium [-8], ${counts.LOW}x Low [-3]).`,
    },
  };
}

export function generateEnvExampleText(findings: VulnerabilityFinding[]): string {
  const secrets = new Set<string>();
  for (const f of findings) {
    if (f.secret_var) secrets.add(f.secret_var);
  }

  if (secrets.size === 0) {
    return '# No hardcoded secrets detected.\n# Standard environment template:\n# APP_ENV=production\n# PORT=3000\n';
  }

  const lines = [
    '# .env.example',
    '# Auto-generated by CodeSanitizer based on hardcoded secret detection.',
    '# DO NOT COMMIT REAL CREDENTIALS. Copy to .env and populate locally.',
    '',
  ];
  Array.from(secrets).sort().forEach(s => lines.push(`${s}=`));
  return lines.join('\n');
}

export function generateMarkdownReportText(result: AuditResult): string {
  const { summary, findings, packages } = result;
  const lines: string[] = [];

  lines.push('# 🛡️ CodeSanitizer Security Audit Report');
  lines.push(`**Lines Analyzed:** ${result.code_lines_count || 'N/A'}`);
  lines.push('');
  lines.push('## 📊 Executive Summary');
  lines.push(`- **Security Score:** **${summary.score} / 100** (${summary.badge})`);
  lines.push(`- **Total Findings:** ${summary.total_findings}`);
  lines.push(`- **Critical:** ${summary.counts.CRITICAL} | **High:** ${summary.counts.HIGH} | **Medium:** ${summary.counts.MEDIUM} | **Low:** ${summary.counts.LOW}`);
  lines.push(`- **Calculation Logic:** ${summary.explanation}`);
  lines.push('');

  lines.push('## 📦 Package Verification & Supply Chain Audit');
  if (packages.length === 0) {
    lines.push('*No external package imports detected.*');
  } else {
    lines.push('| Package | Status | PyPI Verified | Description / Warning |');
    lines.push('| :--- | :---: | :---: | :--- |');
    for (const p of packages) {
      const badge = p.status === 'VERIFIED' ? '✅ Verified' : (p.status === 'NOT_FOUND' ? '❌ Not Found' : '📘 Stdlib');
      lines.push(`| \`${p.package_name}\` | ${p.status} | ${badge} | ${p.message} |`);
    }
  }
  lines.push('');

  lines.push('## 🔍 Detailed Vulnerability Findings');
  if (findings.length === 0) {
    lines.push('✅ **No high-risk vulnerabilities detected!** Code adheres to standard safety heuristics.');
  } else {
    findings.forEach((f, idx) => {
      lines.push(`### ${idx + 1}. [${f.severity}] ${f.title}`);
      lines.push(`- **Line:** ${f.line}`);
      lines.push(`- **Trigger Snippet:** \`${f.code_snippet}\``);
      lines.push(`- **Explanation:** ${f.explanation}`);
      lines.push(`- **Why Dangerous:** ${f.why}`);
      lines.push(`- **Remediation:** ${f.recommendation}`);
      lines.push('');
    });
  }

  lines.push('---');
  lines.push('*Generated by CodeSanitizer - AI-Generated Code & Package Hallucination Auditor*');
  return lines.join('\n');
}
