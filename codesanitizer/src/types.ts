export interface VulnerabilityFinding {
  rule_id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  line: number;
  code_snippet: string;
  explanation: string;
  why: string;
  recommendation: string;
  vulnerable_example?: string | null;
  recommended_example?: string | null;
  secret_var?: string | null;
}

export interface PackageVerificationResult {
  package_name: string;
  status: 'VERIFIED' | 'NOT_FOUND' | 'STDLIB' | 'ERROR' | 'LOCAL';
  exists_on_pypi: boolean;
  is_stdlib: boolean;
  version?: string | null;
  summary?: string | null;
  homepage?: string | null;
  message: string;
  lines: number[];
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  SAFE: number;
}

export interface AuditSummary {
  score: number;
  status: string;
  badge: string;
  total_penalty: number;
  counts: SeverityCounts;
  total_findings: number;
  explanation: string;
}

export interface AuditResult {
  success: boolean;
  error_type?: string | null;
  message: string;
  details?: {
    line?: number;
    offset?: number;
    text?: string;
  };
  summary: AuditSummary;
  findings: VulnerabilityFinding[];
  packages: PackageVerificationResult[];
  code_lines_count?: number;
}

export interface ProjectFileInfo {
  path: string;
  title: string;
  role: string;
  description: string;
  language: string;
}
