export type Page = 'overview' | 'components' | 'scanner' | 'audit' | 'policy';
export interface Finding {
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  evidence: unknown;
  location?: unknown;
  layer: string;
  line?: number;
  encoding?: string;
}
export interface Change {
  path: string;
  old: unknown;
  new: unknown;
  severity: string;
  category: string;
}
export interface Component {
  id: string;
  name: string;
  kind: string;
  source_path: string;
  state: string;
  snapshot_valid: boolean;
  source_valid: boolean;
  version: number;
  raw_hash: string;
  canonical_hash: string;
  semantic_fingerprint: string;
  approved_at: string | null;
  approved_by: string | null;
  approval_id: string | null;
  previous_version: number | null;
  action: string;
  severity: string;
  changes: Change[];
  findings: Finding[];
  content: unknown;
  updated_at: string;
}
export interface Status {
  components: number;
  approved: number;
  pending: number;
  blocked: number;
  scans: number;
  audit_valid: boolean;
  monitor_running: boolean;
  policy_version: number;
  enforcement_mode: string;
  data_dir: string;
  scanner_sandbox?: { available: boolean; error: string | null; landlock_abi?: number | null };
}
export interface ScanReport {
  id: string;
  filename: string;
  sha256: string;
  status: string;
  verdict: Verdict;
  risk_score: number;
  severity: string;
  findings: Finding[];
  extraction: { format: string; characters: number; segments: number; truncated: boolean };
  rules_version: string;
  created_at: string;
  duration_ms: number;
  limitations: string[];
  source_path?: string;
  size_bytes?: number;
  sandbox?: { active: boolean; mechanism: string; landlock_abi?: number };
}
export interface AuditEvent {
  sequence: number;
  timestamp: string;
  event_type: string;
  component_id: string | null;
  details: unknown;
  previous_hash: string;
  hash: string;
}
export interface Policy {
  version: number;
  format_only_action: string;
  semantic_change_action: string;
  security_change_action: string;
  unapproved_action: string;
  scan_block_score: number;
  scan_quarantine_score: number;
  scan_flag_score: number;
}
export interface Monitor {
  running: boolean;
  paths: string[];
  errors: unknown[];
}
export interface Verification {
  valid: boolean;
  checked: number;
  error?: string;
  head_hash?: string;
}

export type Verdict = 'VALID' | 'INFECTED' | 'CORRUPTED' | 'REVIEW_REQUIRED' | 'UNSCANNABLE';
export interface ScanStats {
  analyzed: number;
  matched: number;
  infected: number;
  corrupted: number;
  valid: number;
  review_required: number;
  unscannable: number;
  blocked: number;
  unique_files: number;
  last_scan_at: string | null;
}

export interface FileWatchJob {
  id: string;
  root_id: string;
  status: 'RUNNING' | 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'BUSY' | 'CANCELLED';
  started_at: string;
  completed_at: string | null;
  files_seen: number;
  scanned: number;
  unchanged: number;
  skipped: number;
  failed: number;
  removed: number;
  limited: boolean;
  report_ids: string[];
  errors: { path: string; code: string; message: string }[];
  duration_ms: number;
}
export interface FileWatchRoot {
  id: string;
  path: string;
  recursive: boolean;
  enabled: boolean;
  files_seen: number;
  last_scan_at: string | null;
  error: string | null;
  last_job: FileWatchJob | null;
}
export interface FileWatchStatus {
  running: boolean;
  roots: FileWatchRoot[];
}

export interface Sanitization {
  id: string;
  created_at: string;
  profile: 'html-text-v1';
  transformation_status: 'SANITIZED' | 'FAILED';
  delivery_status: 'ALLOWED' | 'DENIED';
  reason: string;
  input_filename: string;
  output_filename: string;
  input_sha256: string | null;
  output_sha256: string | null;
  input_size_bytes: number | null;
  output_size_bytes: number | null;
  input_report_id: string;
  output_report_id: string | null;
  omitted_counts: Record<string, number>;
}

export interface SanitizationResult extends Sanitization {
  delivery: {
    encoding: 'base64';
    media_type: 'text/plain;charset=utf-8';
    data_base64: string;
  } | null;
}
