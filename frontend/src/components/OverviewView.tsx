import React from 'react';
import {
  ArrowDownLeft,
  ArrowUpRight,
  AlertCircle,
  Rocket,
  Check,
  ShieldAlert,
  Code2,
  FileText,
  Clock,
  Sparkles,
  Layers,
} from 'lucide-react';
import {
  VulnerabilityFinding,
  SecurityPostureMetrics,
  NavigationTab,
  ScanRecord,
} from '../types/security';

interface OverviewViewProps {
  findings: VulnerabilityFinding[];
  scans: ScanRecord[];
  metrics: SecurityPostureMetrics;
  onSelectTab: (tab: NavigationTab) => void;
  onInspectVulnerability: (id: string, targetTab?: NavigationTab) => void;
}

const MATRIX_FEATURES = [
  { name: 'AST Taint Analysis', cols: [true, true, true, true, false] },
  { name: 'Zero-Shell Exec', cols: [true, true, false, false, false] },
  { name: 'Sandbox Replay', cols: [true, false, true, false, true] },
  { name: 'Semantic AST Diff', cols: [true, false, true, true, false] },
  { name: 'Zero Regression', cols: [true, true, false, true, true] },
];

export const OverviewView: React.FC<OverviewViewProps> = ({
  findings,
  scans,
  metrics,
  onSelectTab,
  onInspectVulnerability,
}) => {
  const topThreeFindings = findings.slice(0, 3);

  // Dynamic Donut percentages based on user's real findings
  const total = metrics.totalFindings;
  const validatedPct =
    total > 0 ? Math.round((metrics.validatedCount / total) * 1000) / 10 : 0;
  const autoFixPct =
    total > 0 ? Math.round((metrics.autoFixableCount / total) * 1000) / 10 : 0;
  const unresolvedPct =
    total > 0
      ? Math.max(0, Math.round((100 - validatedPct - autoFixPct) * 10) / 10)
      : 0;

  // Empty State: Displayed before the user submits code
  if (metrics.totalScans === 0) {
    return (
      <div className="space-y-6">
        {/* Empty State Hero Card */}
        <div className="bg-white text-[#0A0A0A] rounded-[30px] p-8 sm:p-10 shadow-sm border border-black/5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
            <div className="max-w-2xl">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold mb-4">
                <Sparkles className="w-3.5 h-3.5 text-[#0A0A0A]" />
                <span>Deterministic AST Security Platform</span>
              </div>
              <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-[#0A0A0A] leading-tight">
                No analysis available. Submit your source code to begin.
              </h1>
              <p className="mt-3 text-sm text-[#52525B] leading-relaxed">
                Paste your custom Python code or upload an entire project ZIP archive. VULNEX AI will statically trace untrusted ingress to execution sinks using Bandit, Semgrep, and our custom AST transformation pipeline.
              </p>
            </div>

            <button
              type="button"
              onClick={() => onSelectTab('new-scan')}
              className="px-8 py-4 rounded-full bg-[#0A0A0A] text-white text-sm font-extrabold hover:bg-[#27272A] transition-all flex items-center gap-2.5 shadow-md cursor-pointer shrink-0 self-start sm:self-center"
            >
              <span>Submit Code for Analysis</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Initial Baseline Dashboard Statistics (Strictly 0s prior to scan) */}
        <div>
          <h2 className="text-xs font-mono font-bold text-[#52525B] uppercase tracking-wider mb-3">
            Initial Posture Baseline
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { label: 'Total Scans', val: metrics.totalScans, icon: Layers },
              { label: 'Vulnerabilities', val: metrics.totalFindings, icon: ShieldAlert },
              { label: 'Critical Findings', val: metrics.criticalOpenCount, icon: AlertCircle },
              { label: 'High Findings', val: metrics.highOpenCount, icon: AlertCircle },
              { label: 'Medium Findings', val: metrics.mediumOpenCount, icon: AlertCircle },
              { label: 'Verified Patches', val: metrics.validatedCount, icon: Check },
              { label: 'Regression Tests', val: metrics.regressionTestsCount, icon: Rocket },
            ].map((stat) => {
              const Icon = stat.icon;
              return (
                <div
                  key={stat.label}
                  className="bg-white rounded-[20px] p-4 text-[#0A0A0A] border border-black/5 flex flex-col justify-between min-h-[110px]"
                >
                  <div className="flex items-center justify-between text-[#52525B]">
                    <span className="text-[11px] font-semibold">{stat.label}</span>
                    <Icon className="w-3.5 h-3.5 opacity-60" />
                  </div>
                  <div className="text-3xl font-extrabold font-mono tabular-nums mt-2">
                    {stat.val}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Architectural Overview Card (Empty Session) */}
        <div className="bg-[#0A0A0A] text-white rounded-[30px] p-8 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div>
            <h3 className="text-xl font-bold tracking-tight text-white">
              Deterministic AST Synthesis & Zero Regression Engine
            </h3>
            <p className="text-xs text-[#A1A1AA] mt-1 max-w-xl leading-relaxed">
              Every vulnerability is identified with concrete line numbers and CWE classification. AI-assisted remediation produces isolated diffs that must genuinely pass multi-stage security validation.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onSelectTab('new-scan')}
            className="px-6 py-3 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-xs font-bold hover:bg-white transition-colors cursor-pointer shrink-0"
          >
            Launch First Scan
          </button>
        </div>
      </div>
    );
  }

  // Active Session State: Displayed once user has executed scans
  return (
    <div className="space-y-5">
      {/* =====================================================================
          ROW 1: Dynamic Security Analysis Overview + Security Posture Hero
         ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left Card: Security Analysis Overview (replaces Patch Velocity) */}
        <section className="lg:col-span-5 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between shadow-sm">
          <div className="flex items-start justify-between gap-4">
            <div>
              <span className="px-3 py-1 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-[11px] font-extrabold uppercase tracking-wide">
                Dynamic Analysis
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight leading-tight mt-2">
                Security Analysis Overview
              </h2>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab('remediation')}
              aria-label="Open Remediation Workbench"
              className="w-10 h-10 rounded-full border border-[#0A0A0A]/25 flex items-center justify-center text-[#0A0A0A] hover:bg-[#0A0A0A] hover:text-white transition-colors shrink-0 cursor-pointer"
            >
              <ArrowDownLeft className="w-4 h-4" />
            </button>
          </div>

          <div className="my-5 grid grid-cols-2 gap-3">
            <div className="p-3.5 rounded-[18px] bg-[#F4F8FB] border border-[#0A0A0A]/5">
              <span className="text-[11px] text-[#52525B] font-medium block">Total Scans</span>
              <span className="text-2xl font-bold font-mono text-[#0A0A0A] mt-1 block tabular-nums">
                {metrics.totalScans}
              </span>
            </div>
            <div className="p-3.5 rounded-[18px] bg-[#F4F8FB] border border-[#0A0A0A]/5">
              <span className="text-[11px] text-[#52525B] font-medium block">Lines Analyzed</span>
              <span className="text-2xl font-bold font-mono text-[#0A0A0A] mt-1 block tabular-nums">
                {metrics.totalLinesAnalyzed}
              </span>
            </div>
            <div className="p-3.5 rounded-[18px] bg-[#F4F8FB] border border-[#0A0A0A]/5">
              <span className="text-[11px] text-[#52525B] font-medium block">Vulnerability Density</span>
              <span className="text-2xl font-bold font-mono text-[#0A0A0A] mt-1 block tabular-nums">
                {metrics.vulnerabilityDensity}%
              </span>
            </div>
            <div className="p-3.5 rounded-[18px] bg-[#F4F8FB] border border-[#0A0A0A]/5">
              <span className="text-[11px] text-[#52525B] font-medium block">Avg Scan Duration</span>
              <span className="text-2xl font-bold font-mono text-[#0A0A0A] mt-1 block tabular-nums">
                {metrics.averageScanDurationMs > 0 ? `${(metrics.averageScanDurationMs / 1000).toFixed(2)}s` : '0.1s'}
              </span>
            </div>
          </div>

          {/* Dynamic CWE Distribution Tags */}
          <div className="pt-3 border-t border-[#0A0A0A]/10">
            <span className="text-[11px] font-bold text-[#52525B] uppercase block mb-2">
              Detected CWE Classification
            </span>
            <div className="flex flex-wrap gap-1.5">
              {Object.keys(metrics.cweDistribution).length > 0 ? (
                Object.entries(metrics.cweDistribution).map(([cwe, count]) => (
                  <span
                    key={cwe}
                    className="px-2.5 py-1 rounded-full bg-[#0A0A0A] text-white text-[11px] font-mono font-bold"
                  >
                    {cwe}: {count}
                  </span>
                ))
              ) : (
                <span className="text-xs text-[#059669] font-medium">
                  Zero CWE violations identified
                </span>
              )}
            </div>
          </div>
        </section>

        {/* Right Card: Solid Obsidian Hero Module */}
        <section className="lg:col-span-7 bg-[#0A0A0A] text-white rounded-[30px] p-7 flex flex-col justify-between">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
            <div className="md:col-span-7 flex flex-col justify-between h-full">
              <div className="flex items-center gap-2.5">
                <span className="w-6 h-6 rounded-full bg-white text-[#0A0A0A] flex items-center justify-center">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                    <circle cx="8" cy="8" r="4.2" />
                    <circle cx="16" cy="8" r="4.2" />
                    <circle cx="8" cy="16" r="4.2" />
                    <circle cx="16" cy="16" r="4.2" />
                  </svg>
                </span>
                <span className="text-xs font-bold tracking-tight text-white">
                  VULNEX AST STUDIO
                </span>
              </div>

              <div className="mt-6">
                <h1 className="text-3xl sm:text-4xl xl:text-5xl font-bold tracking-tight leading-[1.05] text-white">
                  Live Security Posture &amp; Remediation
                </h1>
              </div>

              <div className="mt-5 flex items-center justify-between">
                <p className="text-xs text-[#A1A1AA] max-w-xs leading-relaxed">
                  Static taint analysis paired with strict multi-stage validation ensures zero regression before deployment.
                </p>
                <button
                  type="button"
                  onClick={() => onSelectTab('vulnerabilities')}
                  aria-label="Explore All Vulnerability Findings"
                  className="w-10 h-10 rounded-full border border-white/25 flex items-center justify-center text-white hover:bg-[#D8ECF8] hover:text-[#0A0A0A] hover:border-[#D8ECF8] transition-colors shrink-0 cursor-pointer"
                >
                  <ArrowDownLeft className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* 2x2 Live Telemetry Grid */}
            <div className="md:col-span-5 grid grid-cols-2 gap-2.5">
              <div className="bg-[#18181B] border border-white/10 rounded-[18px] p-3.5 flex flex-col justify-between min-h-[104px]">
                <span className="text-[10px] font-mono text-[#D8ECF8]">LINES_ANALYZED</span>
                <div>
                  <div className="text-lg font-bold font-mono tabular-nums text-white">
                    {metrics.totalLinesAnalyzed}
                  </div>
                  <div className="text-[11px] text-[#A1A1AA]">Source LOC</div>
                </div>
              </div>
              <div className="bg-[#D8ECF8] text-[#0A0A0A] rounded-[18px] p-3.5 flex flex-col justify-between min-h-[104px]">
                <span className="text-[10px] font-mono text-[#0A0A0A]/70">VERIFIED_FIXES</span>
                <div>
                  <div className="text-lg font-extrabold font-mono tabular-nums">
                    {metrics.validatedCount}
                  </div>
                  <div className="text-[11px] font-medium text-[#0A0A0A]/80">Patches Passed</div>
                </div>
              </div>
              <div className="bg-[#27272A] text-white rounded-[18px] p-3.5 flex flex-col justify-between min-h-[104px]">
                <span className="text-[10px] font-mono text-[#A1A1AA]">OPEN_VULNS</span>
                <div>
                  <div className="text-lg font-bold font-mono tabular-nums">
                    {metrics.totalFindings - metrics.validatedCount}
                  </div>
                  <div className="text-[11px] text-[#A1A1AA]">Require Fix</div>
                </div>
              </div>
              <div className="bg-[#9BBCD6] text-[#0A0A0A] rounded-[18px] p-3.5 flex flex-col justify-between min-h-[104px]">
                <span className="text-[10px] font-mono text-[#0A0A0A]/75">VALIDATION_TESTS</span>
                <div>
                  <div className="text-lg font-extrabold font-mono tabular-nums">
                    {metrics.regressionTestsCount}
                  </div>
                  <div className="text-[11px] font-medium text-[#0A0A0A]/80">Checks Passed</div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Live Session Info */}
          <div className="mt-7 pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="inline-flex items-center rounded-full border border-white/25 overflow-hidden">
              <span className="bg-[#D8ECF8] text-[#0A0A0A] font-semibold px-3.5 py-1.5 rounded-full">
                Active Scans
              </span>
              <span className="px-3.5 py-1.5 text-white font-mono tabular-nums">
                {metrics.totalScans} in database
              </span>
            </div>

            <button
              type="button"
              onClick={() => onSelectTab('new-scan')}
              className="px-4 py-1.5 rounded-full bg-white text-[#0A0A0A] font-bold hover:bg-[#D8ECF8] transition-colors cursor-pointer"
            >
              Analyze More Code
            </button>

            <div className="inline-flex items-center rounded-full border border-white/25 overflow-hidden">
              <span className="bg-[#D8ECF8] text-[#0A0A0A] font-semibold px-3.5 py-1.5 rounded-full">
                Backend Engine
              </span>
              <span className="px-3.5 py-1.5 text-white font-mono">
                FastAPI + SQLite
              </span>
            </div>
          </div>
        </section>
      </div>

      {/* =====================================================================
          ROW 2: Active Risk Block & Severity Allocation
         ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left: Active Risk Block */}
        <section className="lg:col-span-7 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-6">
            <div>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight leading-none">
                Active Risk Block
              </h2>
              <p className="text-xs text-[#52525B] mt-1.5">
                Top priority vulnerabilities identified in your submitted code. Select any card to launch remediation.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab('vulnerabilities')}
              aria-label="View All Findings Table"
              className="w-10 h-10 rounded-full border border-[#0A0A0A]/25 flex items-center justify-center text-[#0A0A0A] hover:bg-[#0A0A0A] hover:text-white transition-colors shrink-0 cursor-pointer"
            >
              <ArrowDownLeft className="w-4 h-4" />
            </button>
          </div>

          {topThreeFindings.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {topThreeFindings.map((item, idx) => {
                const isCenterObsidian = idx === 1;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onInspectVulnerability(item.id, 'remediation')}
                    className={`group text-left rounded-[24px] p-5 flex flex-col justify-between min-h-[225px] transition-transform duration-150 hover:-translate-y-1 cursor-pointer ${
                      isCenterObsidian
                        ? 'bg-[#0A0A0A] text-white'
                        : 'bg-[#D8ECF8] text-[#0A0A0A]'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span
                        className={`w-10 h-10 rounded-[13px] flex items-center justify-center ${
                          isCenterObsidian
                            ? 'bg-white text-[#0A0A0A]'
                            : 'bg-[#0A0A0A] text-white'
                        }`}
                      >
                        <AlertCircle className="w-5 h-5" />
                      </span>
                      <span className="text-xs font-mono font-extrabold uppercase">
                        {item.cwe}
                      </span>
                    </div>

                    <div className="my-3">
                      <span className="text-[11px] font-mono opacity-70 block">
                        Line {item.lineStart} · {item.severity}
                      </span>
                      <h3 className="text-sm font-bold tracking-tight leading-snug line-clamp-2 mt-1">
                        {item.title}
                      </h3>
                    </div>

                    <div className="pt-2 border-t border-current/10 flex items-center justify-between text-xs font-bold">
                      <span className="text-[11px]">{item.status}</span>
                      <span className="flex items-center gap-1 group-hover:underline">
                        <span>Fix</span>
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="p-8 rounded-[20px] bg-[#F4F8FB] text-center">
              <Check className="w-8 h-8 text-[#059669] mx-auto mb-2" />
              <h3 className="text-sm font-bold text-[#0A0A0A]">
                No vulnerabilities detected in the submitted code.
              </h3>
              <p className="text-xs text-[#52525B] mt-1">
                Your static analysis completed clean with zero security flaws identified.
              </p>
            </div>
          )}
        </section>

        {/* Right: Dynamic Patch Allocation Donut Card */}
        <section className="lg:col-span-5 bg-[#0A0A0A] text-white rounded-[30px] p-7 grid grid-cols-1 sm:grid-cols-12 gap-5 items-stretch">
          <div className="sm:col-span-6 flex flex-col justify-between">
            <div>
              <h2 className="text-2xl font-bold tracking-tight leading-tight">
                Patch State Allocation
              </h2>
              <p className="mt-3 text-xs text-[#A1A1AA] leading-relaxed">
                Tracks resolution states from initial discovery to strict multi-check validation.
              </p>
            </div>

            <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-xs">
              <span className="text-[#A1A1AA]">Total Flaws: {metrics.totalFindings}</span>
              <button
                type="button"
                onClick={() => onSelectTab('remediation')}
                className="text-[#D8ECF8] font-bold hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>Remediate</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="sm:col-span-6 bg-white text-[#0A0A0A] rounded-[24px] p-4 flex flex-col items-center justify-between">
            <div className="w-full flex items-center justify-between text-[11px] font-bold">
              <span>Verified Rate</span>
              <span className="font-mono tabular-nums">{validatedPct}%</span>
            </div>

            <div className="my-2 relative flex items-center justify-center">
              <svg width="128" height="128" viewBox="0 0 42 42" className="-rotate-90">
                <circle
                  cx="21"
                  cy="21"
                  r="15.915"
                  fill="transparent"
                  stroke="#E5F2FA"
                  strokeWidth="6.5"
                />
                {validatedPct > 0 && (
                  <circle
                    cx="21"
                    cy="21"
                    r="15.915"
                    fill="transparent"
                    stroke="#0A0A0A"
                    strokeWidth="6.5"
                    strokeDasharray={`${validatedPct} ${100 - validatedPct}`}
                    strokeDashoffset="0"
                  />
                )}
                {autoFixPct > 0 && (
                  <circle
                    cx="21"
                    cy="21"
                    r="15.915"
                    fill="transparent"
                    stroke="#87B2D0"
                    strokeWidth="6.5"
                    strokeDasharray={`${autoFixPct} ${100 - autoFixPct}`}
                    strokeDashoffset={`-${validatedPct}`}
                  />
                )}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-xl font-extrabold tracking-tight tabular-nums">
                  {metrics.totalFindings}
                </span>
                <span className="text-[10px] font-semibold text-[#52525B]">
                  findings
                </span>
              </div>
            </div>

            <div className="w-full space-y-1 text-[10px] font-semibold">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-[#0A0A0A]" />
                  <span>Validated</span>
                </span>
                <span className="font-mono tabular-nums">{metrics.validatedCount}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-[#87B2D0]" />
                  <span>Auto-Fixable</span>
                </span>
                <span className="font-mono tabular-nums">{metrics.autoFixableCount}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-[#E5F2FA]" />
                  <span>Unresolved</span>
                </span>
                <span className="font-mono tabular-nums">{metrics.unresolvedCount}</span>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* =====================================================================
          ROW 3: Repository Ledger (Real Scans) & Verification Matrix
         ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        <section className="lg:col-span-7 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-5">
            <div>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight leading-none">
                Scan Execution Ledger
              </h2>
              <p className="text-xs text-[#52525B] mt-1">
                Real scan executions recorded in the local SQLite database.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab('scan-history')}
              aria-label="Open Full Scan History"
              className="w-10 h-10 rounded-full border border-[#0A0A0A]/25 flex items-center justify-center text-[#0A0A0A] hover:bg-[#0A0A0A] hover:text-white transition-colors shrink-0 cursor-pointer"
            >
              <ArrowDownLeft className="w-4 h-4" />
            </button>
          </div>

          <div className="bg-[#0A0A0A] rounded-[24px] p-4 overflow-x-auto">
            <div className="min-w-[500px] space-y-2">
              <div className="grid grid-cols-5 gap-2">
                {['TARGET / FILE', 'LINES', 'DURATION', 'FLAWS', 'STATUS'].map((hdr) => (
                  <div
                    key={hdr}
                    className="bg-[#D8ECF8] text-[#0A0A0A] rounded-full py-2 px-3 text-center text-[10px] font-extrabold tracking-tight"
                  >
                    {hdr}
                  </div>
                ))}
              </div>

              {scans.slice(0, 4).map((scan) => (
                <div key={scan.id} className="grid grid-cols-5 gap-2">
                  <div className="bg-[#D8ECF8] text-[#0A0A0A] rounded-full py-2.5 px-3 text-center text-[11px] font-bold truncate">
                    {scan.repository}
                  </div>
                  <div className="bg-white text-[#0A0A0A] rounded-full py-2.5 px-3 text-center text-[11px] font-mono tabular-nums font-semibold">
                    {scan.totalLinesScanned || scan.totalFilesScanned}
                  </div>
                  <div className="bg-white text-[#0A0A0A] rounded-full py-2.5 px-3 text-center text-[11px] font-mono tabular-nums font-semibold">
                    {scan.duration}
                  </div>
                  <div className="bg-white text-[#0A0A0A] rounded-full py-2.5 px-3 text-center text-[11px] font-mono tabular-nums font-semibold">
                    {scan.criticalCount + scan.highCount + scan.mediumCount}
                  </div>
                  <div className="bg-white text-[#0A0A0A] rounded-full py-2.5 px-3 text-center text-[10px] font-mono font-bold">
                    {scan.status}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Verification Matrix */}
        <section className="lg:col-span-5 bg-[#D8ECF8] text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
          <div className="flex items-center justify-between gap-4 mb-4">
            <h2 className="text-2xl font-bold tracking-tight leading-none">
              Verification Matrix
            </h2>
            <span className="text-xs font-semibold text-[#0A0A0A]/70">
              VULNEX Pipeline vs Legacy
            </span>
          </div>

          <div className="overflow-x-auto">
            <div className="min-w-[420px] space-y-2.5">
              <div className="grid grid-cols-12 gap-2 items-center">
                <div className="col-span-4" />
                <div className="col-span-8 grid grid-cols-4 gap-2 items-center">
                  <div className="bg-[#0A0A0A] text-white rounded-full py-1 px-1.5 text-center text-[10px] font-bold">
                    VULNEX
                  </div>
                  <div className="bg-white/80 text-[#0A0A0A] rounded-full py-1 px-1.5 text-center text-[9px] font-bold">
                    REGEX
                  </div>
                  <div className="bg-white/80 text-[#0A0A0A] rounded-full py-1 px-1.5 text-center text-[9px] font-bold">
                    LLM CHAT
                  </div>
                  <div className="bg-white/80 text-[#0A0A0A] rounded-full py-1 px-1.5 text-center text-[9px] font-bold">
                    MANUAL
                  </div>
                </div>
              </div>

              {MATRIX_FEATURES.map((row) => (
                <div key={row.name} className="grid grid-cols-12 gap-2 items-center">
                  <div className="col-span-4 bg-white text-[#0A0A0A] rounded-full py-2 px-3 text-[11px] font-bold whitespace-nowrap truncate">
                    {row.name}
                  </div>
                  <div className="col-span-8 bg-white/90 rounded-full py-1.5 grid grid-cols-4 items-center">
                    {row.cols.slice(0, 4).map((supported, cIdx) => (
                      <div key={cIdx} className="flex items-center justify-center">
                        {supported ? (
                          <span className="w-4 h-4 rounded-full bg-[#0A0A0A] text-white flex items-center justify-center">
                            <Check className="w-2.5 h-2.5 stroke-[3]" />
                          </span>
                        ) : (
                          <span className="w-2 h-0.5 bg-[#0A0A0A]/20 rounded-full" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
