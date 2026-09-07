"""
package_checker.py - Live PyPI Package Verification & Hallucination Auditor
Part of CodeSanitizer - AI-Generated Code & Package Hallucination Auditor.

Uses asynchronous HTTP requests with httpx (with standard urllib fallback)
to check whether third-party packages exist on the live PyPI API.
Accurately excludes Python standard library modules.
"""

import sys
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Optional, Any

# Python 3.10+ standard library module detection
try:
    STDLIB_MODULES: Set[str] = set(sys.stdlib_module_names)
except AttributeError:
    # Comprehensive fallback for standard library modules
    STDLIB_MODULES: Set[str] = {
        "__future__", "_thread", "abc", "aifc", "argparse", "array", "ast",
        "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64",
        "bdb", "binascii", "binhex", "bisect", "builtins", "bz2", "calendar",
        "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop",
        "collections", "colorsys", "compileall", "concurrent", "configparser",
        "contextlib", "contextvars", "copy", "copyreg", "crypt", "csv",
        "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
        "difflib", "dis", "distutils", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
        "heapq", "hmac", "html", "http", "imaplib", "imghdr", "imp",
        "importlib", "inspect", "io", "ipaddress", "itertools", "json",
        "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
        "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc",
        "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
        "parser", "pathlib", "pdb", "pickle", "pickletools", "pipes",
        "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath",
        "pprint", "profile", "pstats", "pty", "pwd", "py_compile",
        "pyclbr", "pydoc", "queue", "quopri", "random", "re", "readline",
        "reprlib", "resource", "rlcompleter", "runpy", "sched", "secrets",
        "select", "selectors", "shelve", "shlex", "shutil", "signal",
        "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
        "spwd", "sqlite3", "sre_compile", "sre_constants", "sre_parse",
        "ssl", "stat", "statistics", "string", "stringprep", "struct",
        "subprocess", "sunau", "symbol", "symtable", "sys", "sysconfig",
        "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
        "test", "textwrap", "threading", "time", "timeit", "tkinter",
        "token", "tokenize", "trace", "traceback", "tracemalloc", "tty",
        "turtle", "turtledemo", "types", "typing", "unicodedata", "unittest",
        "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
        "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml",
        "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo"
    }

# Known common local modules or relative package prefixes that are standard/safe
INTERNAL_SAFE_MODULES = {"test_code", "rules", "analyzer", "package_checker", "report"}


@dataclass
class PackageVerificationResult:
    package_name: str
    status: str  # "VERIFIED", "NOT_FOUND", "STDLIB", "ERROR"
    exists_on_pypi: bool
    is_stdlib: bool
    version: Optional[str] = None
    summary: Optional[str] = None
    homepage: Optional[str] = None
    message: str = ""
    lines: List[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_package_name(import_target: str) -> str:
    """
    Extracts the root package name from an import statement.
    Example:
      'requests.auth' -> 'requests'
      'flask.views' -> 'flask'
      'google.genai' -> 'google' (or checks package registry)
    """
    cleaned = import_target.strip().split(".")[0]
    return cleaned.lower()


def is_standard_library(package_name: str) -> bool:
    """Determines whether a module belongs to the Python standard library."""
    norm = package_name.strip().lower()
    return norm in STDLIB_MODULES


async def verify_single_package_async(
    client: Any,
    package_name: str,
    lines: List[int]
) -> PackageVerificationResult:
    """
    Asynchronously queries the PyPI JSON API: https://pypi.org/pypi/{package}/json
    """
    norm_name = package_name.lower()

    # 1. Check Standard Library
    if is_standard_library(norm_name):
        return PackageVerificationResult(
            package_name=package_name,
            status="STDLIB",
            exists_on_pypi=False,
            is_stdlib=True,
            message="Python Standard Library Module (Verified built-in)",
            lines=lines,
        )

    # 2. Check local project files
    if norm_name in INTERNAL_SAFE_MODULES:
        return PackageVerificationResult(
            package_name=package_name,
            status="LOCAL",
            exists_on_pypi=False,
            is_stdlib=False,
            message="Local Application Module",
            lines=lines,
        )

    url = f"https://pypi.org/pypi/{package_name}/json"
    headers = {
        "User-Agent": "CodeSanitizer-Auditor/1.0 (Cybersecurity Hackathon Tool)"
    }

    try:
        response = await client.get(url, headers=headers, timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            info = data.get("info", {})
            version = info.get("version", "Unknown")
            summary = info.get("summary", "No description provided.")
            home = info.get("home_page") or info.get("project_url") or f"https://pypi.org/project/{package_name}/"
            return PackageVerificationResult(
                package_name=package_name,
                status="VERIFIED",
                exists_on_pypi=True,
                is_stdlib=False,
                version=version,
                summary=summary,
                homepage=home,
                message="Package exists on PyPI (Live Verified)",
                lines=lines,
            )
        elif response.status_code == 404:
            return PackageVerificationResult(
                package_name=package_name,
                status="NOT_FOUND",
                exists_on_pypi=False,
                is_stdlib=False,
                message="Package DOES NOT EXIST on PyPI. High risk of AI package hallucination or typo-squatting attack.",
                lines=lines,
            )
        else:
            return PackageVerificationResult(
                package_name=package_name,
                status="ERROR",
                exists_on_pypi=False,
                is_stdlib=False,
                message=f"PyPI API returned status {response.status_code}",
                lines=lines,
            )
    except Exception as e:
        # Graceful handling of network timeouts or DNS failures
        return PackageVerificationResult(
            package_name=package_name,
            status="ERROR",
            exists_on_pypi=False,
            is_stdlib=False,
            message=f"Network/API error during PyPI check: {type(e).__name__}",
            lines=lines,
        )


async def check_packages_async(
    imports_map: Dict[str, List[int]]
) -> List[PackageVerificationResult]:
    """
    Checks multiple packages concurrently using httpx.AsyncClient.
    If httpx is unavailable, falls back to synchronous verification.
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            tasks = [
                verify_single_package_async(client, pkg, lines)
                for pkg, lines in imports_map.items()
            ]
            results = await asyncio.gather(*tasks)
            return list(results)
    except ImportError:
        # Fallback to sync verification using urllib.request
        return check_packages_sync(imports_map)


def verify_single_package_sync(package_name: str, lines: List[int]) -> PackageVerificationResult:
    """Synchronous fallback verification using urllib.request."""
    import urllib.request
    import json

    norm_name = package_name.lower()
    if is_standard_library(norm_name):
        return PackageVerificationResult(
            package_name=package_name,
            status="STDLIB",
            exists_on_pypi=False,
            is_stdlib=True,
            message="Python Standard Library Module (Verified built-in)",
            lines=lines,
        )

    if norm_name in INTERNAL_SAFE_MODULES:
        return PackageVerificationResult(
            package_name=package_name,
            status="LOCAL",
            exists_on_pypi=False,
            is_stdlib=False,
            message="Local Application Module",
            lines=lines,
        )

    url = f"https://pypi.org/pypi/{package_name}/json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "CodeSanitizer-Auditor/1.0 (Cybersecurity Hackathon Tool)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                info = data.get("info", {})
                return PackageVerificationResult(
                    package_name=package_name,
                    status="VERIFIED",
                    exists_on_pypi=True,
                    is_stdlib=False,
                    version=info.get("version"),
                    summary=info.get("summary", ""),
                    homepage=info.get("home_page"),
                    message="Package exists on PyPI (Live Verified)",
                    lines=lines,
                )
    except urllib.error.HTTPError as he:
        if he.code == 404:
            return PackageVerificationResult(
                package_name=package_name,
                status="NOT_FOUND",
                exists_on_pypi=False,
                is_stdlib=False,
                message="Package DOES NOT EXIST on PyPI. Potential AI-hallucinated dependency.",
                lines=lines,
            )
        return PackageVerificationResult(
            package_name=package_name,
            status="ERROR",
            exists_on_pypi=False,
            is_stdlib=False,
            message=f"PyPI HTTP Error {he.code}",
            lines=lines,
        )
    except Exception as ex:
        return PackageVerificationResult(
            package_name=package_name,
            status="ERROR",
            exists_on_pypi=False,
            is_stdlib=False,
            message=f"Network error checking PyPI: {type(ex).__name__}",
            lines=lines,
        )


def check_packages_sync(imports_map: Dict[str, List[int]]) -> List[PackageVerificationResult]:
    """Synchronous package checking wrapper."""
    results = []
    for pkg, lines in imports_map.items():
        results.append(verify_single_package_sync(pkg, lines))
    return results


def run_package_verification(imports_map: Dict[str, List[int]]) -> List[PackageVerificationResult]:
    """
    Entrypoint that safely executes async checking within active or new event loops.
    Works seamlessly in Streamlit, CLI scripts, and backend servers.
    """
    if not imports_map:
        return []

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # In an already running event loop (e.g. some Streamlit contexts)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                return executor.submit(
                    lambda: asyncio.run(check_packages_async(imports_map))
                ).result()
        else:
            return loop.run_until_complete(check_packages_async(imports_map))
    except Exception:
        # Fallback to sync verification
        return check_packages_sync(imports_map)
