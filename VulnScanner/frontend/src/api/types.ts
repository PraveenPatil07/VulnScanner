export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanStatus = 'idle' | 'uploading' | 'scanning' | 'generating_report' | 'completed' | 'error';

export interface Finding {
  id?: string;
  scan_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: string;
  category: string;
  cwe_id: string;
  cvss_score: number;
  cvss_vector: string;
  mitre_attack_id: string | null;
  nist_csf: string[];
  owasp_top10: string | null;
  file_path: string;
  line_number: number;
  column_start: number;
  column_end: number;
  code_snippet: string;
  match_text: string;
  remediation: string;
  references: string[];
  false_positive_risk: string | null;
  language: string;
}

export interface ScanResult {
  scan_id: string;
  status: string;
  total_files: number;
  files_scanned: number;
  lines_scanned: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  findings_by_category: Record<string, number>;
  findings_by_language: Record<string, number>;
  findings: Finding[];
  scan_duration_ms: number;
  llm_report?: string;
  completed_at?: string;
  error?: string;
}

export interface ScanProgress {
  scan_id: string;
  status: ScanStatus;
  files_scanned: number;
  total_files: number;
  current_file?: string;
  findings_so_far: number;
}

export interface SSEEvent {
  event: string;
  data: string;
}

export interface HealthResponse {
  status: string;
  version: string;
}
