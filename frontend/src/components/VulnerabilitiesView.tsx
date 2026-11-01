import React, { useState } from 'react';
import {
  Search,
  Copy,
  Check,
  ArrowUpRight,
  Wrench,
  RotateCcw,
} from 'lucide-react';
import {
  VulnerabilityFinding,
  VulnerabilityStatus,
  SeverityLevel,
  NavigationTab,
} from '../types/security';
import { filterVulnerabilities } from '../utils/securityEngine';

interface VulnerabilitiesViewProps {
  findings: VulnerabilityFinding[];
  selectedId: string;
  onSelectFinding: (id: string) => void;
  onOpenWorkbench: (id: string, tab?: NavigationTab) => void;
}

const STATUS_TABS: ('All' | VulnerabilityStatus)[] = [
  'All',
  'Unresolved',
  'Auto-Fixable',
  'Validated',
];

const SEVERITY_TABS: ('ALL' | SeverityLevel)[] = [
  'ALL',
  'CRITICAL',
  'HIGH',
  'MEDIUM',
];

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  findings,
  selectedId,
  onSelectFinding,
  onOpenWorkbench,
}) => {
  const [statusFilter, setStatusFilter] = useState<'All' | VulnerabilityStatus>('All');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | SeverityLevel>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filtered = filterVulnerabilities(findings, {
    statusFilter,
    severityFilter,
    searchQuery,
  });

  const activeFinding =
    filtered.find((f) => f.id === selectedId) ||
    filtered[0] ||
    findings.find((f) => f.id === selectedId) ||
    findings[0];

  const handleCopySnippet = (finding: VulnerabilityFinding) => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(finding.vulnerableSnippet).catch(() => {});
    }
    setCopiedId(finding.id);
    setTimeout(() => {
      setCopiedId((prev) => (prev === finding.id ? null : prev));
    }, 1800);
  };

  const getSeverityBadgeStyle = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-[#E11D48] text-white';
      case 'HIGH':
        return 'bg-[#D97706] text-white';
      case 'MEDIUM':
      case 'LOW':
      default:
        return 'bg-[#64748B] text-white';
    }
  };

  const getStatusBadgeStyle = (status: VulnerabilityStatus) => {
    switch (status) {
      case 'Validated':
        return 'bg-[#059669] text-white';
      case 'Auto-Fixable':
        return 'bg-[#D8ECF8] text-[#0A0A0A]';
      case 'Unresolved':
      default:
        return 'bg-[#0A0A0A] text-white';
    }
  };

  if (findings.length === 0) {
    return (
      <div className="bg-white text-[#0A0A0A] rounded-[30px] p-10 text-center shadow-sm border border-black/5">
        <div className="max-w-md mx-auto py-8">
          <div className="w-16 h-16 rounded-full bg-[#E5F2FA] text-[#0A0A0A] flex items-center justify-center mx-auto mb-4">
            <Search className="w-8 h-8 opacity-70" />
          </div>
          <h2 className="text-2xl font-extrabold tracking-tight text-[#0A0A0A]">
            No vulnerabilities detected yet. Run your first scan.
          </h2>
          <p className="text-xs text-[#52525B] mt-2 leading-relaxed">
            Submit your source code or project ZIP archive to trigger static security analysis using Bandit, Semgrep, and our custom AST transformation pipeline.
          </p>
          <button
            type="button"
            onClick={() => onOpenWorkbench('', 'new-scan')}
            className="mt-6 px-7 py-3.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors cursor-pointer inline-flex items-center gap-2"
          >
            <span>Launch New AST Scan</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Top Filter & Search Bar Card */}
      <section className="bg-white text-[#0A0A0A] rounded-[30px] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight leading-none">
              Vulnerability Findings
            </h1>
            <p className="text-xs text-[#52525B] mt-1.5">
              Deterministic AST taint sinks discovered across active repositories. Filter by remediation readiness or severity.
            </p>
          </div>

          {/* Search Input */}
          <div className="relative w-full lg:w-80">
            <Search className="w-4 h-4 text-[#71717A] absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              aria-label="Search vulnerability findings"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search CWE, file path, or sink..."
              className="w-full pl-10 pr-4 py-2.5 rounded-full bg-[#E5F2FA] text-xs font-medium text-[#0A0A0A] placeholder:text-[#52525B] focus:outline-none focus:ring-2 focus:ring-[#0A0A0A]"
            />
          </div>
        </div>

        {/* Interactive Filter Pill Bars */}
        <div className="mt-5 pt-5 border-t border-[#0A0A0A]/10 flex flex-wrap items-center justify-between gap-4">
          {/* Status Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by status">
            {STATUS_TABS.map((tab) => {
              const active = statusFilter === tab;
              const count =
                tab === 'All'
                  ? findings.length
                  : findings.filter((f) => f.status === tab).length;
              return (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setStatusFilter(tab)}
                  className={`px-4 py-2 rounded-full text-xs font-bold transition-colors flex items-center gap-2 cursor-pointer whitespace-nowrap ${
                    active
                      ? 'bg-[#0A0A0A] text-white'
                      : 'bg-[#D8ECF8]/70 text-[#0A0A0A] hover:bg-[#D8ECF8]'
                  }`}
                >
                  <span>{tab}</span>
                  <span
                    className={`font-mono text-[11px] tabular-nums px-2 py-0.5 rounded-full ${
                      active ? 'bg-white/20 text-white' : 'bg-white text-[#0A0A0A]'
                    }`}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Severity Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by severity">
            {SEVERITY_TABS.map((sev) => {
              const active = severityFilter === sev;
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-3.5 py-1.5 rounded-full text-[11px] font-bold transition-colors cursor-pointer whitespace-nowrap ${
                    active
                      ? 'bg-[#0A0A0A] text-white'
                      : 'bg-[#F4F8FB] text-[#52525B] hover:text-[#0A0A0A] border border-[#0A0A0A]/10'
                  }`}
                >
                  {sev}
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Main Split View: Findings List (7 cols) + Code Snippet & AST Inspector (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Findings Cards / Table */}
        <div className="lg:col-span-7 space-y-3">
          {filtered.length === 0 ? (
            <div className="bg-white rounded-[30px] p-10 text-center">
              <div className="text-xl font-bold text-[#0A0A0A]">
                No matching AST findings
              </div>
              <p className="text-xs text-[#52525B] mt-2 max-w-sm mx-auto">
                No vulnerabilities match the current status, severity, or search query filters.
              </p>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('All');
                  setSeverityFilter('ALL');
                  setSearchQuery('');
                }}
                className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Filters</span>
              </button>
            </div>
          ) : (
            filtered.map((item) => {
              const isSelected = activeFinding?.id === item.id;
              return (
                <div
                  key={item.id}
                  onClick={() => onSelectFinding(item.id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectFinding(item.id);
                    }
                  }}
                  aria-label={`Select finding ${item.id} ${item.title}`}
                  className={`rounded-[26px] p-5 transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-[#0A0A0A] text-white shadow-sm'
                      : 'bg-white text-[#0A0A0A] hover:bg-[#F8FBFE]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`w-9 h-9 rounded-[12px] font-mono text-xs font-extrabold flex items-center justify-center ${
                          isSelected
                            ? 'bg-[#D8ECF8] text-[#0A0A0A]'
                            : 'bg-[#0A0A0A] text-white'
                        }`}
                      >
                        {item.indexBadge}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold opacity-75">
                            {item.id}
                          </span>
                          <span aria-hidden="true" className="opacity-40">·</span>
                          <span className="font-mono text-xs font-semibold opacity-75">
                            {item.cwe}
                          </span>
                          <span aria-hidden="true" className="opacity-40">·</span>
                          <span className="font-mono text-xs font-bold tabular-nums opacity-90">
                            CVSS {item.cvss.toFixed(1)}
                          </span>
                        </div>
                        <h2 className="text-base font-bold tracking-tight mt-0.5">
                          {item.title}
                        </h2>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span
                        className={`px-3 py-1 rounded-full text-[11px] font-bold tracking-tight ${getSeverityBadgeStyle(
                          item.severity
                        )}`}
                      >
                        {item.severity}
                      </span>
                      <span
                        className={`px-3 py-1 rounded-full text-[11px] font-bold tracking-tight ${getStatusBadgeStyle(
                          item.status
                        )}`}
                      >
                        {item.status}
                      </span>
                    </div>
                  </div>

                  <p
                    className={`mt-3 text-xs leading-relaxed ${
                      isSelected ? 'text-[#A1A1AA]' : 'text-[#52525B]'
                    }`}
                  >
                    {item.summary}
                  </p>

                  <div
                    className={`mt-4 pt-3 border-t flex flex-wrap items-center justify-between gap-2 text-xs ${
                      isSelected ? 'border-white/10' : 'border-[#0A0A0A]/10'
                    }`}
                  >
                    <div className="flex items-center gap-2 font-mono text-[11px]">
                      <span
                        className={`px-2.5 py-1 rounded-full ${
                          isSelected
                            ? 'bg-white/10 text-[#D8ECF8]'
                            : 'bg-[#E5F2FA] text-[#0A0A0A]'
                        }`}
                      >
                        {item.repository}
                      </span>
                      <span className="opacity-80">
                        {item.filePath}:{item.lineStart}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenWorkbench(item.id, 'remediation');
                      }}
                      className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold transition-colors cursor-pointer ${
                        isSelected
                          ? 'bg-[#D8ECF8] text-[#0A0A0A] hover:bg-white'
                          : 'bg-[#0A0A0A] text-white hover:bg-[#27272A]'
                      }`}
                    >
                      <Wrench className="w-3.5 h-3.5" />
                      <span>Remediate Patch</span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Selected Finding Code Snippet Viewer & AST Metadata */}
        {activeFinding && (
          <div className="lg:col-span-5 bg-[#0A0A0A] text-white rounded-[30px] p-6 space-y-5 sticky top-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-xs font-extrabold font-mono">
                    {activeFinding.id}
                  </span>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityBadgeStyle(
                      activeFinding.severity
                    )}`}
                  >
                    {activeFinding.severity} · {activeFinding.cvss}
                  </span>
                </div>
                <h3 className="text-xl font-bold tracking-tight mt-3">
                  {activeFinding.title}
                </h3>
              </div>

              <button
                type="button"
                onClick={() => onOpenWorkbench(activeFinding.id, 'remediation')}
                aria-label="Open selected finding in Remediation Workbench"
                className="w-10 h-10 rounded-full border border-white/25 flex items-center justify-center text-white hover:bg-[#D8ECF8] hover:text-[#0A0A0A] hover:border-[#D8ECF8] transition-colors shrink-0 cursor-pointer"
              >
                <ArrowUpRight className="w-4 h-4" />
              </button>
            </div>

            {/* Minimalist Code Snippet Viewer Header */}
            <div className="bg-[#141414] border border-white/10 rounded-[22px] overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 bg-[#1C1C1F] border-b border-white/10">
                <div className="flex items-center gap-2">
                  <span className="px-3 py-1 rounded-full bg-white text-[#0A0A0A] font-mono text-[11px] font-bold">
                    {activeFinding.filePath}
                  </span>
                  <span className="px-2.5 py-1 rounded-full bg-white/10 text-[#D8ECF8] font-mono text-[11px] tabular-nums">
                    L{activeFinding.lineStart}–L{activeFinding.lineEnd}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopySnippet(activeFinding)}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-[11px] font-bold hover:bg-white transition-colors cursor-pointer"
                >
                  {copiedId === activeFinding.id ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Snippet</span>
                    </>
                  )}
                </button>
              </div>

              {/* Vulnerable Code Display */}
              <pre className="p-4 text-xs font-mono leading-relaxed text-[#E4E4E7] overflow-x-auto">
                <code>{activeFinding.vulnerableSnippet}</code>
              </pre>
            </div>

            {/* Glacier Ice-Blue Callout Card for AST Node & Root Cause */}
            <div className="bg-[#D8ECF8] text-[#0A0A0A] rounded-[22px] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-extrabold tracking-tight">
                  AST Taint Sink Analysis
                </span>
                <span className="px-2.5 py-0.5 rounded-full bg-[#0A0A0A] text-white font-mono text-[10px]">
                  {activeFinding.cwe}
                </span>
              </div>

              <p className="text-xs text-[#0A0A0A]/85 leading-relaxed">
                {activeFinding.rootCauseAnalysis}
              </p>

              <div className="pt-2 border-t border-[#0A0A0A]/10 flex items-center justify-between text-[11px] font-mono">
                <span className="font-bold">AST Node:</span>
                <span className="truncate max-w-[230px]">
                  {activeFinding.astNodeTarget}
                </span>
              </div>
            </div>

            {/* Bottom Action Buttons */}
            <div className="flex items-center gap-3 pt-1">
              <button
                type="button"
                onClick={() => onOpenWorkbench(activeFinding.id, 'remediation')}
                className="flex-1 py-3 px-5 rounded-full bg-white text-[#0A0A0A] text-xs font-extrabold hover:bg-[#D8ECF8] transition-colors flex items-center justify-center gap-2 cursor-pointer"
              >
                <Wrench className="w-4 h-4" />
                <span>Inspect &amp; Approve AST Patch</span>
              </button>
              <button
                type="button"
                onClick={() => onOpenWorkbench(activeFinding.id, 'validation-lab')}
                className="py-3 px-4 rounded-full border border-white/20 text-white text-xs font-bold hover:bg-white/10 transition-colors cursor-pointer whitespace-nowrap"
              >
                Sandbox Lab
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
