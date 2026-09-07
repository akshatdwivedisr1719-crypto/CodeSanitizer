"""
rules.py - Security Rules, Finding Definitions, and Deterministic Risk Engine
Part of CodeSanitizer - AI-Generated Code & Package Hallucination Auditor.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


# Severity deduction weights for calculating security score (0 - 100)
SEVERITY_DEDUCTIONS: Dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.SAFE: 0,
}

SEVERITY_ICONS: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "SAFE": "🟢",
}

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "SAFE": "#22c55e",
}


@dataclass
class VulnerabilityFinding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    line: int
    code_snippet: str
    explanation: str
    why: str
    recommendation: str
    vulnerable_example: Optional[str] = None
    recommended_example: Optional[str] = None
    secret_var: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_security_score(findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
    """
    Deterministically computes an overall security score from 0 to 100.
    
    Formula:
      Base Score = 100
      Total Penalty = Sum of severity deductions for each vulnerability
      Security Score = Max(0, 100 - Total Penalty)
    
    Penalties:
      - CRITICAL: -30 points each
      - HIGH:     -15 points each
      - MEDIUM:   -8 points each
      - LOW:      -3 points each
    """
    total_penalty = 0
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "SAFE": 0,
    }

    for finding in findings:
        sev = finding.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        # Deduct score according to severity
        try:
            sev_enum = Severity(sev)
            total_penalty += SEVERITY_DEDUCTIONS.get(sev_enum, 5)
        except ValueError:
            total_penalty += 5

    score = max(0, min(100, 100 - total_penalty))

    # Determine qualitative status
    if score >= 90:
        status = "EXCELLENT"
        badge = "🟢 SAFE & COMPLIANT"
    elif score >= 75:
        status = "ACCEPTABLE"
        badge = "🟡 MINOR WARNINGS"
    elif score >= 50:
        status = "NEEDS_IMPROVEMENT"
        badge = "🟠 ELEVATED RISK"
    else:
        status = "CRITICAL_RISK"
        badge = "🔴 HAZARDOUS"

    return {
        "score": score,
        "status": status,
        "badge": badge,
        "total_penalty": total_penalty,
        "counts": severity_counts,
        "total_findings": len(findings),
        "explanation": (
            f"Score calculated deterministically starting at 100 minus weighted penalties "
            f"({severity_counts['CRITICAL']}x Critical [-30], {severity_counts['HIGH']}x High [-15], "
            f"{severity_counts['MEDIUM']}x Medium [-8], {severity_counts['LOW']}x Low [-3])."
        ),
    }
