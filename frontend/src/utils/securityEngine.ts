import {
  VulnerabilityFinding,
  VulnerabilityStatus,
  SeverityLevel,
  SecurityPostureMetrics,
  ScanFormInput,
  ScanRecord,
} from '../types/security';

export interface VulnerabilityFilterOptions {
  statusFilter: 'All' | VulnerabilityStatus;
  severityFilter: 'ALL' | SeverityLevel;
  searchQuery: string;
}

export function calculateSecurityMetrics(
  findings: VulnerabilityFinding[],
  scans: ScanRecord[] = []
): SecurityPostureMetrics {
  const totalScans = scans.length;
  const totalFindings = findings.length;
  const unresolvedCount = findings.filter((f) => f.status === 'Unresolved').length;
  const autoFixableCount = findings.filter((f) => f.status === 'Auto-Fixable').length;
  const validatedCount = findings.filter((f) => f.status === 'Validated').length;

  const openFindings = findings.filter((f) => f.status !== 'Validated');
  const criticalOpenCount = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highOpenCount = openFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumOpenCount = openFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowOpenCount = openFindings.filter((f) => f.severity === 'LOW').length;

  const totalLinesAnalyzed = scans.reduce((acc, s) => acc + (s.totalLinesScanned || 0), 0);
  const totalFilesAnalyzed = scans.reduce((acc, s) => acc + (s.totalFilesScanned || 1), 0);
  const averageScanDurationMs =
    scans.length > 0
      ? Math.round(scans.reduce((acc, s) => acc + (s.durationMs || 0), 0) / scans.length)
      : 0;

  const vulnerabilityDensity =
    totalLinesAnalyzed > 0
      ? Number(((totalFindings / totalLinesAnalyzed) * 100).toFixed(2))
      : 0;

  const regressionTestsCount = findings.reduce(
    (acc, f) => acc + (f.validationChecklist ? f.validationChecklist.filter((c) => c.passed).length : 0),
    0
  );

  const cweDistribution: { [cwe: string]: number } = {};
  findings.forEach((f) => {
    const cweKey = f.cwe || 'CWE-UNKNOWN';
    cweDistribution[cweKey] = (cweDistribution[cweKey] || 0) + 1;
  });

  return {
    totalScans,
    totalFindings,
    unresolvedCount,
    autoFixableCount,
    validatedCount,
    criticalOpenCount,
    highOpenCount,
    mediumOpenCount,
    lowOpenCount,
    totalLinesAnalyzed,
    totalFilesAnalyzed,
    vulnerabilityDensity,
    averageScanDurationMs,
    regressionTestsCount,
    cweDistribution,
  };
}

export function filterVulnerabilities(
  findings: VulnerabilityFinding[],
  options: VulnerabilityFilterOptions
): VulnerabilityFinding[] {
  const query = options.searchQuery.trim().toLowerCase();

  return findings.filter((item) => {
    if (options.statusFilter !== 'All' && item.status !== options.statusFilter) {
      return false;
    }
    if (options.severityFilter !== 'ALL' && item.severity !== options.severityFilter) {
      return false;
    }
    if (query.length > 0) {
      const hay = [
        item.id,
        item.title,
        item.category,
        item.cwe,
        item.repository,
        item.filePath,
        item.summary,
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(query)) {
        return false;
      }
    }
    return true;
  });
}

export function approveVulnerabilityPatch(
  findings: VulnerabilityFinding[],
  vulnerabilityId: string
): VulnerabilityFinding[] {
  return findings.map((item) => {
    if (item.id !== vulnerabilityId) return item;
    return {
      ...item,
      status: 'Validated',
      validationChecklist: item.validationChecklist.map((chk) => ({
        ...chk,
        passed: true,
      })),
    };
  });
}

export interface ScanValidationResult {
  valid: boolean;
  error?: string;
  normalizedRepo?: string;
  normalizedBranch?: string;
}

export function validateScanInput(input: ScanFormInput): ScanValidationResult {
  const rawRepo = input.repository.trim();
  const rawBranch = input.branch.trim();

  if (!rawRepo) {
    return {
      valid: false,
      error: 'Target repository path or URL is required (e.g. vulnex-core/payment-ledger).',
    };
  }

  // Must look like org/repo or domain/org/repo and contain no whitespace
  if (/\s/.test(rawRepo) || !rawRepo.includes('/') || rawRepo.length < 5) {
    return {
      valid: false,
      error: 'Enter a valid repository identifier in org/repo format (e.g. vulnex-core/payment-ledger).',
    };
  }

  if (!rawBranch) {
    return {
      valid: false,
      error: 'Target git branch name is required (e.g. main).',
    };
  }

  const normalizedRepo = rawRepo
    .replace(/^https?:\/\/(www\.)?github\.com\//i, '')
    .replace(/\.git$/i, '');

  return {
    valid: true,
    normalizedRepo,
    normalizedBranch: rawBranch,
  };
}
