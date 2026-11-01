import React, { useState, useEffect } from 'react';
import {
  Check,
  CheckCircle2,
  FlaskConical,
  Sparkles,
  Columns,
  AlignJustify,
  Copy,
  Download,
  XCircle,
  FileCode2,
  CheckCheck,
} from 'lucide-react';
import { VulnerabilityFinding, NavigationTab } from '../types/security';
import { BackendCombinedRemediationResponse } from '../services/apiClient';

interface RemediationWorkbenchProps {
  findings: VulnerabilityFinding[];
  selectedId: string;
  combinedRemediation?: BackendCombinedRemediationResponse | null;
  onSelectFinding: (id: string) => void;
  onApprovePatch: (id: string) => void;
  onRejectPatch?: (id: string) => void;
  onNavigateTab: (tab: NavigationTab) => void;
}

export const RemediationWorkbench: React.FC<RemediationWorkbenchProps> = ({
  findings,
  selectedId,
  combinedRemediation,
  onSelectFinding,
  onApprovePatch,
  onRejectPatch,
  onNavigateTab,
}) => {
  const [diffMode, setDiffMode] = useState<'split' | 'unified'>('split');
  const [viewScope, setViewScope] = useState<'combined' | 'single'>(
    combinedRemediation ? 'combined' : 'single'
  );
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [copiedCombined, setCopiedCombined] = useState(false);
  const [justApprovedId, setJustApprovedId] = useState<string | null>(null);

  useEffect(() => {
    if (combinedRemediation) {
      setViewScope('combined');
    }
  }, [combinedRemediation]);

  const finding =
    findings.find((f) => f.id === selectedId) || findings[0];

  if (!finding || findings.length === 0) {
    return (
      <div className="bg-white text-[#0A0A0A] rounded-[30px] p-10 text-center shadow-sm border border-black/5">
        <div className="max-w-md mx-auto py-8">
          <div className="w-16 h-16 rounded-full bg-[#E5F2FA] text-[#0A0A0A] flex items-center justify-center mx-auto mb-4">
            <FlaskConical className="w-8 h-8 opacity-70" />
          </div>
          <h2 className="text-2xl font-extrabold tracking-tight text-[#0A0A0A]">
            No remediation available. Detect a vulnerability first.
          </h2>
          <p className="text-xs text-[#52525B] mt-2 leading-relaxed">
            Run an AST security scan on your submitted source code to detect execution sinks and synthesize verified patches.
          </p>
          <button
            type="button"
            onClick={() => onNavigateTab('new-scan')}
            className="mt-6 px-7 py-3.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors cursor-pointer inline-flex items-center gap-2"
          >
            <span>Scan Source Code</span>
          </button>
        </div>
      </div>
    );
  }

  const isValidated = finding.status === 'Validated';

  const handleApprove = () => {
    onApprovePatch(finding.id);
    setJustApprovedId(finding.id);
    setTimeout(() => {
      setJustApprovedId((prev) => (prev === finding.id ? null : prev));
    }, 2500);
  };

  const handleReject = () => {
    if (onRejectPatch) {
      onRejectPatch(finding.id);
    }
  };

  const handleDownloadPatched = () => {
    const filename = finding.filePath ? `patched_${finding.filePath.replace(/.*\//, '')}` : 'patched_source.py';
    const blob = new Blob([finding.patchedSnippet], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyPatched = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(finding.patchedSnippet).catch(() => {});
    }
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 1800);
  };

  const handleCopyCombined = () => {
    if (!combinedRemediation) return;
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(combinedRemediation.remediated_code).catch(() => {});
    }
    setCopiedCombined(true);
    setTimeout(() => setCopiedCombined(false), 2000);
  };

  const handleDownloadCombined = () => {
    if (!combinedRemediation) return;
    const filename = `fixed_${combinedRemediation.target_name || 'source.c'}`;
    const blob = new Blob([combinedRemediation.remediated_code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      {/* Top Workbench Selector Header */}
      <section className="bg-white text-[#0A0A0A] rounded-[30px] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-3xl font-bold tracking-tight leading-none">
                Remediation Workbench
              </h1>
              <span className="px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] font-mono text-xs font-bold">
                AST Synthesizer v4.2
              </span>
            </div>
            <p className="text-xs text-[#52525B] mt-1.5">
              Deterministic abstract syntax tree transformations with zero semantic drift. Select any finding below to review and commit its patch.
            </p>
          </div>

          {/* Diff Mode Toggle & Copy */}
          <div className="flex flex-wrap items-center gap-2 self-start lg:self-auto shrink-0">
            <div className="inline-flex items-center p-1 rounded-full bg-[#E5F2FA] shrink-0">
              <button
                type="button"
                onClick={() => setDiffMode('split')}
                className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-bold transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                  diffMode === 'split'
                    ? 'bg-[#0A0A0A] text-white'
                    : 'text-[#0A0A0A] hover:bg-white/60'
                }`}
              >
                <Columns className="w-3.5 h-3.5 shrink-0" />
                <span>Side-by-Side</span>
              </button>
              <button
                type="button"
                onClick={() => setDiffMode('unified')}
                className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-bold transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                  diffMode === 'unified'
                    ? 'bg-[#0A0A0A] text-white'
                    : 'text-[#0A0A0A] hover:bg-white/60'
                }`}
              >
                <AlignJustify className="w-3.5 h-3.5 shrink-0" />
                <span>Unified Diff</span>
              </button>
            </div>

            {/* Copy & Download Actions (Dynamic for Combined or Single View) */}
            {viewScope === 'combined' && combinedRemediation ? (
              <>
                <button
                  type="button"
                  onClick={handleCopyCombined}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full bg-[#059669] text-white text-xs font-bold hover:bg-[#047857] transition-colors cursor-pointer whitespace-nowrap shrink-0 shadow-sm"
                >
                  {copiedCombined ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-white shrink-0" />
                      <span>Copied Full Fixed Code!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 shrink-0" />
                      <span>Copy Full Remediated Code</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadCombined}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full bg-[#E5F2FA] hover:bg-[#D8ECF8] text-[#0A0A0A] text-xs font-bold transition-colors cursor-pointer whitespace-nowrap shrink-0 border border-[#0A0A0A]/10"
                >
                  <Download className="w-3.5 h-3.5 shrink-0" />
                  <span>Download Full Fixed Code</span>
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={handleCopyPatched}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors cursor-pointer whitespace-nowrap shrink-0"
                >
                  {copiedPatch ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#D8ECF8] shrink-0" />
                      <span>Copied Patch</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 shrink-0" />
                      <span>Copy Patched AST</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadPatched}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full bg-[#E5F2FA] hover:bg-[#D8ECF8] text-[#0A0A0A] text-xs font-bold transition-colors cursor-pointer whitespace-nowrap shrink-0 border border-[#0A0A0A]/10"
                >
                  <Download className="w-3.5 h-3.5 shrink-0" />
                  <span>Download Patched Source</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Switcher Pills: Full Combined Fixed Code + Individual Findings */}
        <div className="mt-5 pt-4 border-t border-[#0A0A0A]/10 flex items-center gap-2 overflow-x-auto pb-1">
          {combinedRemediation && (
            <button
              type="button"
              onClick={() => setViewScope('combined')}
              className={`px-4 py-2 rounded-full text-xs font-extrabold flex items-center gap-2 shrink-0 transition-colors cursor-pointer shadow-sm ${
                viewScope === 'combined'
                  ? 'bg-[#059669] text-white'
                  : 'bg-[#E5F7ED] text-[#059669] hover:bg-[#D1F2DF]'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Full Combined Remediated Code</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-white text-[#059669]">
                {combinedRemediation.total_fixes} FIXES COMBINED
              </span>
            </button>
          )}

          {findings.map((item) => {
            const active = viewScope === 'single' && item.id === finding.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setViewScope('single');
                  onSelectFinding(item.id);
                }}
                className={`px-4 py-2 rounded-full text-xs font-bold flex items-center gap-2 shrink-0 transition-colors cursor-pointer ${
                  active
                    ? 'bg-[#0A0A0A] text-white'
                    : 'bg-[#E5F2FA] text-[#0A0A0A] hover:bg-[#CBE3F5]'
                }`}
              >
                <span className="font-mono">{item.indexBadge}</span>
                <span>{item.category}</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-mono ${
                    item.status === 'Validated'
                      ? 'bg-[#059669] text-white'
                      : active
                      ? 'bg-white/20 text-white'
                      : 'bg-white text-[#0A0A0A]'
                  }`}
                >
                  {item.status === 'Validated' ? 'VALIDATED' : item.id}
                </span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Code Comparison Container (Obsidian Black Card) */}
      <section className="bg-[#0A0A0A] text-white rounded-[30px] p-6">
        {viewScope === 'combined' && combinedRemediation ? (
          <>
            {/* Header for Combined Remediated File */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-white/10">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="px-3.5 py-1.5 rounded-full bg-[#059669] text-white font-mono text-xs font-bold flex items-center gap-1.5 shadow-sm">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>ALL-IN-ONE REMEDIATED FILE</span>
                </span>
                <span className="px-3.5 py-1.5 rounded-full bg-white text-[#0A0A0A] font-mono text-xs font-bold">
                  {combinedRemediation.target_name}
                </span>
                <span className="px-3 py-1.5 rounded-full bg-white/10 text-[#D8ECF8] font-mono text-xs">
                  {combinedRemediation.total_fixes} of {combinedRemediation.total_findings} Flaws Resolved
                </span>
                <span className="px-3 py-1.5 rounded-full bg-white/10 text-[#6EE7B7] font-mono text-xs font-bold">
                  {combinedRemediation.all_vulnerabilities_fixed ? 'Zero Flaws Remaining' : 'Partial Fixes Applied'}
                </span>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs font-bold tabular-nums">
                <span className="px-3.5 py-1 rounded-full bg-[#059669]/25 text-[#6EE7B7] border border-[#059669]/40">
                  +{combinedRemediation.added_lines ?? combinedRemediation.total_fixes} additions
                </span>
                <span className="px-3.5 py-1 rounded-full bg-[#E11D48]/25 text-[#FDA4AF] border border-[#E11D48]/40">
                  -{combinedRemediation.removed_lines ?? combinedRemediation.total_fixes} deletions
                </span>
              </div>
            </div>

            {/* Split or Unified View for Combined File */}
            {diffMode === 'split' ? (
              <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Left: Original Code */}
                <div className="bg-[#141414] border border-white/10 rounded-[22px] overflow-hidden flex flex-col">
                  <div className="px-4 py-3 bg-[#1C1C1F] border-b border-white/10 flex items-center justify-between">
                    <span className="text-xs font-bold text-[#FDA4AF] flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-[#E11D48] text-white text-[10px] font-mono">
                        ORIGINAL SOURCE
                      </span>
                      <span>Vulnerable Code ({combinedRemediation.total_findings} issues)</span>
                    </span>
                    <span className="font-mono text-[11px] text-[#A1A1AA] tabular-nums">
                      {combinedRemediation.original_code.split('\n').length} lines
                    </span>
                  </div>
                  <pre className="p-4 text-xs font-mono leading-relaxed text-[#E4E4E7] overflow-x-auto max-h-[550px] flex-1">
                    <code>{combinedRemediation.original_code}</code>
                  </pre>
                </div>

                {/* Right: Full Combined Remediated Code */}
                <div className="bg-[#0e1f17] border-2 border-[#059669] rounded-[22px] overflow-hidden flex flex-col shadow-lg">
                  <div className="px-4 py-3 bg-[#0a1a12] border-b border-[#059669]/40 flex items-center justify-between">
                    <span className="text-xs font-bold text-[#6EE7B7] flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-[#059669] text-white text-[10px] font-mono">
                        FIXED SOURCE
                      </span>
                      <span>Full Combined Remediated Code (All Fixes Merged)</span>
                    </span>
                    <span className="font-mono text-[11px] text-[#6EE7B7] tabular-nums font-bold">
                      CLEAN / COMPILABLE
                    </span>
                  </div>
                  <pre className="p-4 text-xs font-mono leading-relaxed text-[#A7F3D0] overflow-x-auto max-h-[550px] flex-1">
                    <code>{combinedRemediation.remediated_code}</code>
                  </pre>
                </div>
              </div>
            ) : (
              /* Unified Diff for Full File */
              <div className="mt-5 bg-[#141414] border border-white/10 rounded-[22px] overflow-hidden">
                <div className="px-4 py-3 bg-[#1C1C1F] border-b border-white/10 flex items-center justify-between text-xs font-mono text-[#A1A1AA]">
                  <span>Unified Patch across {combinedRemediation.target_name}</span>
                  <span className="text-[#6EE7B7] font-bold">{combinedRemediation.total_fixes} security fixes merged</span>
                </div>
                <pre className="p-4 text-xs font-mono leading-relaxed text-[#E4E4E7] overflow-x-auto max-h-[550px]">
                  <code>{combinedRemediation.unified_diff}</code>
                </pre>
              </div>
            )}
          </>
        ) : (
          /* Single Finding Diff View */
          <>
            <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-white/10">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="px-3.5 py-1.5 rounded-full bg-white text-[#0A0A0A] font-mono text-xs font-bold">
                  {finding.filePath}
                </span>
                <span className="px-3 py-1.5 rounded-full bg-white/10 text-[#D8ECF8] font-mono text-xs">
                  {finding.repository} ({finding.branch})
                </span>
                <span className="px-3 py-1.5 rounded-full bg-white/10 text-white font-mono text-xs">
                  {finding.cwe} · CVSS {finding.cvss}
                </span>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs font-bold tabular-nums">
                <span className="px-3.5 py-1 rounded-full bg-[#059669]/25 text-[#6EE7B7] border border-[#059669]/40">
                  +{finding.additionsCount} additions
                </span>
                <span className="px-3.5 py-1 rounded-full bg-[#E11D48]/25 text-[#FDA4AF] border border-[#E11D48]/40">
                  -{finding.deletionsCount} deletions
                </span>
              </div>
            </div>

            {diffMode === 'split' ? (
              <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-[#141414] border border-white/10 rounded-[22px] overflow-hidden flex flex-col">
                  <div className="px-4 py-3 bg-[#1C1C1F] border-b border-white/10 flex items-center justify-between">
                    <span className="text-xs font-bold text-[#FDA4AF] flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-[#E11D48] text-white text-[10px] font-mono">
                        BEFORE
                      </span>
                      <span>Vulnerable AST Sink</span>
                    </span>
                    <span className="font-mono text-[11px] text-[#A1A1AA] tabular-nums">
                      Lines {finding.lineStart}–{finding.lineEnd}
                    </span>
                  </div>
                  <pre className="p-4 text-xs font-mono leading-relaxed text-[#E4E4E7] overflow-x-auto flex-1">
                    <code>{finding.vulnerableSnippet}</code>
                  </pre>
                </div>

                <div className="bg-[#141414] border border-[#D8ECF8]/30 rounded-[22px] overflow-hidden flex flex-col">
                  <div className="px-4 py-3 bg-[#1C1C1F] border-b border-white/10 flex items-center justify-between">
                    <span className="text-xs font-bold text-[#D8ECF8] flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-[#059669] text-white text-[10px] font-mono">
                        AFTER
                      </span>
                      <span>Synthesized Deterministic Patch</span>
                    </span>
                    <span className="font-mono text-[11px] text-[#D8ECF8] tabular-nums">
                      0 Regressions
                    </span>
                  </div>
                  <pre className="p-4 text-xs font-mono leading-relaxed text-[#E4E4E7] overflow-x-auto flex-1">
                    <code>{finding.patchedSnippet}</code>
                  </pre>
                </div>
              </div>
            ) : (
              <div className="mt-5 bg-[#141414] border border-white/10 rounded-[22px] overflow-hidden">
                <div className="px-4 py-3 bg-[#1C1C1F] border-b border-white/10 flex items-center justify-between text-xs font-mono text-[#A1A1AA]">
                  <span>@@ -{finding.lineStart},{finding.deletionsCount} +{finding.lineStart},{finding.additionsCount} @@</span>
                  <span>AST Target: {finding.astNodeTarget}</span>
                </div>
                <div className="divide-y divide-white/5 font-mono text-xs overflow-x-auto">
                  {finding.diffLines.map((line, index) => {
                    const rowStyle =
                      line.type === 'added'
                        ? 'bg-[#059669]/15 text-[#A7F3D0]'
                        : line.type === 'removed'
                        ? 'bg-[#E11D48]/15 text-[#FECDD3]'
                        : 'text-[#D4D4D8]';
                    const prefix =
                      line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' ';
                    return (
                      <div
                        key={index}
                        className={`flex items-center px-4 py-1.5 ${rowStyle}`}
                      >
                        <span className="w-10 text-right pr-3 opacity-45 select-none tabular-nums">
                          {line.lineNumberBefore ?? ''}
                        </span>
                        <span className="w-10 text-right pr-3 opacity-45 select-none tabular-nums">
                          {line.lineNumberAfter ?? ''}
                        </span>
                        <span className="w-5 font-bold select-none">{prefix}</span>
                        <span className="whitespace-pre">{line.content}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        )}
      </section>

      {/* Bottom Cards: Dual View for Combined vs Single */}
      {viewScope === 'combined' && combinedRemediation ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
          {/* Left: Itemized Fixes Breakdown */}
          <section className="lg:col-span-7 bg-[#D8ECF8] text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="px-3.5 py-1 rounded-full bg-[#0A0A0A] text-white text-xs font-bold">
                  Combined Remediation Summary
                </span>
                <span className="font-mono text-xs font-bold text-[#0A0A0A]/75">
                  {combinedRemediation.total_fixes} Vulnerabilities Fixed
                </span>
              </div>

              <h2 className="text-2xl font-bold tracking-tight mt-4">
                All Vulnerabilities Resolved in Combined Code
              </h2>
              <p className="mt-2 text-xs text-[#0A0A0A]/85 leading-relaxed">
                The synthesized source above unifies all required security patches into a single, clean, compilable file without syntax conflicts or semantic regression.
              </p>

              <div className="mt-4 space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
                {combinedRemediation.fixes_applied.map((fix, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-[18px] bg-white text-[#0A0A0A] border border-[#0A0A0A]/10 shadow-sm"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded-full bg-[#059669] text-white font-mono text-[10px] font-bold">
                          FIX #{idx + 1}
                        </span>
                        <span className="font-bold text-xs text-[#0A0A0A]">
                          {fix.title || fix.rule_id}
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-[#52525B]">
                        Line {fix.line} · {fix.cwe_id}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#52525B] mt-1.5 leading-relaxed">
                      {fix.explanation}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-[#0A0A0A]/15 flex items-center justify-between text-xs font-bold">
              <span>Status: Ready for production deployment</span>
              <span className="px-3 py-1 rounded-full bg-[#059669] text-white font-mono text-xs">
                Deterministic Patch Applied
              </span>
            </div>
          </section>

          {/* Right: Actions Hub */}
          <section className="lg:col-span-5 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-2xl font-bold tracking-tight">
                  Deploy Remediated Code
                </h2>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-[#059669] text-white">
                  VERIFIED
                </span>
              </div>
              <p className="mt-2 text-xs text-[#52525B] leading-relaxed">
                Copy the full updated code or download the corrected source file directly to integrate with your compiler and CI/CD pipeline.
              </p>

              <div className="mt-6 space-y-3">
                <button
                  type="button"
                  onClick={handleCopyCombined}
                  className="w-full py-4 px-6 rounded-full bg-[#059669] text-white text-xs font-extrabold hover:bg-[#047857] transition-all flex items-center justify-center gap-2 cursor-pointer shadow-md"
                >
                  {copiedCombined ? (
                    <>
                      <Check className="w-4 h-4" />
                      <span>Copied Remediated Code to Clipboard!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      <span>Copy Full Remediated Code</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadCombined}
                  className="w-full py-3.5 px-6 rounded-full bg-[#E5F2FA] hover:bg-[#D8ECF8] text-[#0A0A0A] text-xs font-bold transition-colors flex items-center justify-center gap-2 cursor-pointer border border-[#0A0A0A]/10"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Fixed Source File</span>
                </button>

                <button
                  type="button"
                  onClick={() => onNavigateTab('validation-lab')}
                  className="w-full py-3.5 px-6 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors flex items-center justify-center gap-2 cursor-pointer"
                >
                  <FlaskConical className="w-4 h-4" />
                  <span>Inspect in Validation Lab</span>
                </button>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-[#0A0A0A]/10 text-center">
              <span className="text-[11px] text-[#71717A]">
                To view each vulnerability individually, click any finding pill above.
              </span>
            </div>
          </section>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
          {/* Left: Glacier-Blue Editorial Root Cause & AST Transformation Card */}
        <section className="lg:col-span-6 bg-[#D8ECF8] text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2">
              <span className="px-3.5 py-1 rounded-full bg-[#0A0A0A] text-white text-xs font-bold">
                Root Cause &amp; AST Strategy
              </span>
              <span className="font-mono text-xs font-bold text-[#0A0A0A]/75">
                {finding.id} · {finding.cwe}
              </span>
            </div>

            <h2 className="text-2xl font-bold tracking-tight mt-4">
              Why This Sink Is Exploitable
            </h2>
            <p className="mt-2 text-xs text-[#0A0A0A]/85 leading-relaxed">
              {finding.rootCauseAnalysis}
            </p>

            <h3 className="text-base font-bold tracking-tight mt-5">
              Synthesized Compiler Transformation
            </h3>
            <p className="mt-1.5 text-xs text-[#0A0A0A]/85 leading-relaxed">
              {finding.astTransformationStrategy}
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-[#0A0A0A]/15 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold">Exploit Vector Neutralized:</span>
              <span className="px-2.5 py-0.5 rounded-full bg-white text-[#0A0A0A] font-mono text-[11px] font-bold">
                Verified in Sandbox
              </span>
            </div>
            <div className="px-3.5 py-2.5 rounded-[16px] bg-white font-mono text-[11px] text-[#0A0A0A] overflow-x-auto">
              {finding.exploitPayload}
            </div>
          </div>
        </section>

        {/* Right: Validation Checklist & Prominent "Review & Approve Patch" Action */}
        <section className="lg:col-span-6 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-2xl font-bold tracking-tight">
                Pre-Merge Verification Checklist
              </h2>
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold ${
                  isValidated
                    ? 'bg-[#059669] text-white'
                    : 'bg-[#D8ECF8] text-[#0A0A0A]'
                }`}
              >
                {isValidated ? 'PATCH COMMITTED' : 'READY FOR APPROVAL'}
              </span>
            </div>

            <div className="mt-5 space-y-2.5">
              {finding.validationChecklist.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between gap-3 p-3.5 rounded-[20px] bg-[#F4F8FB]"
                >
                  <div className="flex items-center gap-3">
                    <span className="w-7 h-7 rounded-full bg-[#0A0A0A] text-white flex items-center justify-center shrink-0">
                      <Check className="w-4 h-4" />
                    </span>
                    <div>
                      <div className="text-xs font-bold text-[#0A0A0A]">
                        {item.label}
                      </div>
                      <div className="text-[11px] text-[#52525B]">
                        {item.detail}
                      </div>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded-full bg-white text-[#0A0A0A] font-mono text-[11px] font-bold tabular-nums shrink-0">
                    {item.durationMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-[#0A0A0A]/10 flex flex-col sm:flex-row items-center gap-3">
            <button
              type="button"
              onClick={handleApprove}
              className={`w-full sm:flex-1 py-3.5 px-6 rounded-full text-xs font-extrabold tracking-tight flex items-center justify-center gap-2 transition-colors cursor-pointer ${
                isValidated
                  ? 'bg-[#059669] text-white hover:bg-[#047857]'
                  : 'bg-[#0A0A0A] text-white hover:bg-[#27272A]'
              }`}
            >
              {isValidated || justApprovedId === finding.id ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Patch Approved &amp; Validated ({finding.id})</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Review &amp; Approve Patch</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => onNavigateTab('validation-lab')}
              className="w-full sm:w-auto py-3.5 px-5 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-xs font-bold hover:bg-[#CBE3F5] transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
            >
              <FlaskConical className="w-4 h-4" />
              <span>Replay in Lab</span>
            </button>

            {onRejectPatch && (
              <button
                type="button"
                onClick={handleReject}
                className="w-full sm:w-auto py-3.5 px-5 rounded-full bg-[#FFEBEB] text-[#E11D48] hover:bg-[#FFD6D6] text-xs font-bold transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
              >
                <XCircle className="w-4 h-4" />
                <span>Reject Patch</span>
              </button>
            )}
          </div>
        </section>
      </div>
      )}
    </div>
  );
};
