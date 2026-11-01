export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type VulnerabilityStatus = 'Unresolved' | 'Auto-Fixable' | 'Validated';

export type NavigationTab =
  | 'overview'
  | 'new-scan'
  | 'vulnerabilities'
  | 'remediation'
  | 'validation-lab'
  | 'scan-history'
  | 'iot-analyzer'
  | 'firmware-synthesis';

export interface DiffLine {
  lineNumberBefore?: number;
  lineNumberAfter?: number;
  type: 'context' | 'removed' | 'added';
  content: string;
}

export interface ValidationCriterion {
  id: string;
  label: string;
  detail: string;
  status?: 'PASSED' | 'FAILED' | 'NOT RUN';
  passed: boolean;
  durationMs: number;
}

export interface VulnerabilityFinding {
  id: string;
  indexBadge: string; // e.g. "01.", "02."
  title: string;
  category: string;
  cwe: string;
  cvss: number;
  severity: SeverityLevel;
  status: VulnerabilityStatus;
  repository: string;
  branch: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  detectedAt: string;
  summary: string;
  rootCauseAnalysis: string;
  astTransformationStrategy: string;
  astNodeTarget: string;
  additionsCount: number;
  deletionsCount: number;
  vulnerableSnippet: string;
  patchedSnippet: string;
  diffLines: DiffLine[];
  exploitPayload: string;
  expectedSafeOutput: string;
  validationChecklist: ValidationCriterion[];
}

export interface ScanRecord {
  id: string;
  repository: string;
  branch: string;
  commitHash: string;
  triggeredBy: string;
  timestamp: string;
  duration: string;
  durationMs?: number;
  totalFilesScanned: number;
  totalLinesScanned?: number;
  vulnerabilityDensity?: number;
  astNodesInspected: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount?: number;
  autoPatchedCount: number;
  status: 'SYNTAX VERIFIED' | '0 REGRESSIONS' | 'ACTION REQUIRED' | 'COMPLETED' | 'FAILED' | 'VERIFIED';
  engineProfile: string;
}

export interface ScanFormInput {
  repository: string;
  branch: string;
  engineProfile: 'Full AST + Sandbox Replay' | 'Deterministic Taint Only' | 'Zero-Regression Patch Synth';
  enableAutoPatch: boolean;
  enableSandboxReplay: boolean;
}

export interface SecurityPostureMetrics {
  totalScans: number;
  totalFindings: number;
  unresolvedCount: number;
  autoFixableCount: number;
  validatedCount: number;
  criticalOpenCount: number;
  highOpenCount: number;
  mediumOpenCount: number;
  lowOpenCount: number;
  totalLinesAnalyzed: number;
  totalFilesAnalyzed: number;
  vulnerabilityDensity: number;
  averageScanDurationMs: number;
  regressionTestsCount: number;
  cweDistribution: { [cwe: string]: number };
}

export interface FirmwareTemplate {
  id: string;
  title: string;
  category: string;
  target_platform: string;
  description: string;
  sample_prompt: string;
}

export interface FirmwareAnalysisRequest {
  source_code: string;
  filename?: string;
  target_platform: string;
  rtos?: string;
  security_checks: string[];
}

export interface FirmwareAnalysisResponse {
  scan_id: string;
  target_platform: string;
  rtos?: string;
  status: string;
  lines_of_code: number;
  duration_ms: number;
  firmware_components_analyzed: number;
  risk_breakdown: { [category: string]: number };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  findings: VulnerabilityFinding[];
  tool_status?: { [tool: string]: any };
  created_at: string;
}

export interface FirmwareSynthesisRequest {
  target_platform: string;
  rtos?: string;
  requirement: string;
  component_type?: string;
}

export interface FirmwareSynthesisResponse {
  id: string;
  requirement: string;
  target_platform: string;
  rtos?: string;
  component_type?: string;
  title: string;
  source_code: string;
  header_code: string;
  configuration_file?: string;
  dependencies: string[];
  security_considerations: string[];
  unit_tests?: string;
  explanation: string;
  created_at: string;
}

export interface FirmwareRefactorRequest {
  insecure_code: string;
  vulnerability_type: string;
  target_platform?: string;
}

export interface FirmwareRefactorResponse {
  original_code: string;
  secure_code: string;
  diff: string;
  vulnerability_type: string;
  security_benefits: string[];
  explanation: string;
}
