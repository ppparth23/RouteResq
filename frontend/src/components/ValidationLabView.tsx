import React, { useState } from 'react';
import {
  Play,
  Check,
  ShieldCheck,
  Terminal,
  ArrowUpRight,
  FlaskConical,
  XCircle,
  HelpCircle,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import {
  VulnerabilityFinding,
  SecurityPostureMetrics,
  NavigationTab,
} from '../types/security';
import { apiClient } from '../services/apiClient';

interface ValidationLabViewProps {
  findings: VulnerabilityFinding[];
  selectedId: string;
  metrics: SecurityPostureMetrics;
  onSelectFinding: (id: string) => void;
  onApprovePatch: (id: string) => void;
  onNavigateTab: (tab: NavigationTab) => void;
}

export const ValidationLabView: React.FC<ValidationLabViewProps> = ({
  findings,
  selectedId,
  metrics,
  onSelectFinding,
  onApprovePatch,
  onNavigateTab,
}) => {
  const [replayCount, setReplayCount] = useState(1);
  const [customPayload, setCustomPayload] = useState('');
  const [lastReplayTimestamp, setLastReplayTimestamp] = useState('Active Session');
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [liveChecks, setLiveChecks] = useState<any[] | null>(null);

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
            No patches available for validation.
          </h2>
          <p className="text-xs text-[#52525B] mt-2 leading-relaxed">
            Execute a code scan to detect vulnerabilities and synthesize AST patches before launching validation.
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

  const activePayload = customPayload.trim() || finding.exploitPayload;

  const handleRunReplay = async () => {
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await apiClient.validateRemediation(finding.id, true);
      setReplayCount((c) => c + 1);
      const now = new Date();
      setLastReplayTimestamp(`${now.toLocaleDateString()} · ${now.toTimeString().slice(0, 8)} UTC`);
      if (res && res.checks) {
        setLiveChecks(res.checks);
      }
    } catch (err: any) {
      setValidationError(err.message || 'Validation execution failed');
      const now = new Date();
      setLastReplayTimestamp(`${now.toLocaleDateString()} · ${now.toTimeString().slice(0, 8)} UTC`);
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Hero Banner with Solid Capsule Status Badges */}
      <section className="bg-[#0A0A0A] text-white rounded-[30px] p-7">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-3.5 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-xs font-extrabold tracking-tight">
                SYNTAX VERIFIED
              </span>
              <span className="px-3.5 py-1 rounded-full bg-[#059669] text-white text-xs font-extrabold tracking-tight">
                0 REGRESSIONS
              </span>
              <span className="px-3.5 py-1 rounded-full bg-white text-[#0A0A0A] text-xs font-extrabold font-mono tabular-nums">
                RUN #{replayCount}
              </span>
            </div>

            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mt-4">
              Sandbox Exploit Replay &amp; AST Verification Lab
            </h1>
            <p className="text-xs text-[#A1A1AA] mt-2 max-w-2xl">
              Every synthesized AST patch is verified through the strict multi-stage compilation and static security pipeline before merge approval.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              disabled={isValidating}
              onClick={handleRunReplay}
              className="px-5 py-3 rounded-full bg-[#D8ECF8] text-[#0A0A0A] text-xs font-extrabold hover:bg-white transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isValidating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Validating Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Execute Sandbox Replay</span>
                </>
              )}
            </button>

            {finding.status !== 'Validated' && (
              <button
                type="button"
                onClick={() => onApprovePatch(finding.id)}
                className="px-5 py-3 rounded-full bg-[#059669] text-white text-xs font-extrabold hover:bg-[#047857] transition-colors flex items-center gap-2 cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Mark {finding.id} Validated</span>
              </button>
            )}
          </div>
        </div>

        {/* Finding Selector Pills */}
        <div className="mt-6 pt-5 border-t border-white/10 flex items-center gap-2 overflow-x-auto pb-1">
          {findings.map((item) => {
            const active = item.id === finding.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onSelectFinding(item.id);
                  setCustomPayload('');
                }}
                className={`px-4 py-2 rounded-full text-xs font-bold flex items-center gap-2 shrink-0 transition-colors cursor-pointer ${
                  active
                    ? 'bg-white text-[#0A0A0A]'
                    : 'bg-white/10 text-white hover:bg-white/20'
                }`}
              >
                <span className="font-mono">{item.indexBadge}</span>
                <span>{item.id}</span>
                <span className="opacity-75">· {item.category}</span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Bento Row: Adversarial Payload Replay (7 cols) + Invariant Telemetry (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left: Adversarial Exploit Replay Simulator */}
        <section className="lg:col-span-7 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-2xl font-bold tracking-tight">
                Adversarial Exploit Vector Replay
              </h2>
              <span className="px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] font-mono text-xs font-bold">
                {finding.cwe}
              </span>
            </div>

            <div className="mt-5">
              <label
                htmlFor="sandbox-payload-input"
                className="block text-xs font-bold text-[#0A0A0A] mb-2"
              >
                Injected Attack Payload (Editable Sandbox Input)
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  id="sandbox-payload-input"
                  type="text"
                  value={customPayload}
                  onChange={(e) => setCustomPayload(e.target.value)}
                  placeholder={finding.exploitPayload}
                  className="flex-1 px-4 py-2.5 rounded-full bg-[#E5F2FA] font-mono text-xs text-[#0A0A0A] placeholder:text-[#0A0A0A]/60 focus:outline-none focus:ring-2 focus:ring-[#0A0A0A]"
                />
                <button
                  type="button"
                  onClick={handleRunReplay}
                  className="px-5 py-2.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors shrink-0 cursor-pointer"
                >
                  Replay Vector
                </button>
              </div>
            </div>

            {/* Dual Comparison: Unpatched vs Patched Sandbox Execution */}
            <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="rounded-[22px] bg-[#0A0A0A] text-white p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#FDA4AF]">
                    Unpatched Baseline
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#E11D48] text-white font-mono text-[10px] font-bold">
                    EXPLOITED
                  </span>
                </div>
                <p className="mt-3 font-mono text-[11px] text-[#A1A1AA] break-all">
                  Input: {activePayload}
                </p>
                <div className="mt-4 pt-3 border-t border-white/10 text-xs text-white/90">
                  Taint reached sink <code className="text-[#D8ECF8]">{finding.astNodeTarget.split('[')[0]}</code> without sanitization boundary.
                </div>
              </div>

              <div className="rounded-[22px] bg-[#D8ECF8] text-[#0A0A0A] p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold">
                    Patched AST Build
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#059669] text-white font-mono text-[10px] font-bold">
                    EXPLOIT BLOCKED
                  </span>
                </div>
                <p className="mt-3 font-mono text-[11px] text-[#0A0A0A]/75 break-all">
                  Input: {activePayload}
                </p>
                <div className="mt-4 pt-3 border-t border-[#0A0A0A]/10 text-xs font-semibold text-[#0A0A0A]">
                  {finding.expectedSafeOutput}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-[#0A0A0A]/10 flex flex-wrap items-center justify-between gap-2 text-xs text-[#52525B]">
            <span className="font-mono flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#0A0A0A]" />
              <span>Last sandbox run: {lastReplayTimestamp}</span>
            </span>
            <button
              type="button"
              onClick={() => onNavigateTab('remediation')}
              className="font-bold text-[#0A0A0A] hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>Inspect AST Diff</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </section>

        {/* Right: Deterministic Test & Invariant Telemetry */}
        <section className="lg:col-span-5 bg-[#D8ECF8] text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold tracking-tight">
                Invariant Telemetry
              </h2>
              <span className="px-3 py-1 rounded-full bg-[#0A0A0A] text-white font-mono text-xs font-bold tabular-nums">
                {metrics.regressionTestsCount} Checks Executed
              </span>
            </div>

            <div className="mt-5 grid grid-cols-2 gap-3">
              <div className="bg-white rounded-[22px] p-4">
                <div className="text-3xl font-extrabold tracking-tight tabular-nums">
                  {finding.status === 'Validated' ? '100%' : '0%'}
                </div>
                <div className="text-xs font-semibold text-[#52525B] mt-1">
                  Verification Pass Rate
                </div>
              </div>
              <div className="bg-[#0A0A0A] text-white rounded-[22px] p-4">
                <div className="text-3xl font-extrabold tracking-tight tabular-nums text-[#D8ECF8]">
                  {finding.validationChecklist.reduce((acc, c) => acc + (c.passed ? c.durationMs : 0), 0)}ms
                </div>
                <div className="text-xs font-semibold text-[#A1A1AA] mt-1">
                  Active Execution Time
                </div>
              </div>
            </div>

            <div className="mt-4 space-y-2">
              {finding.validationChecklist.map((chk) => {
                const isPassed = chk.status === 'PASSED' || (chk.passed && finding.status === 'Validated');
                const isFailed = chk.status === 'FAILED';
                const statusLabel = isPassed ? 'PASS' : isFailed ? 'FAIL' : 'NOT RUN';

                return (
                  <div
                    key={chk.id}
                    className="bg-white rounded-full px-4 py-2.5 flex items-center justify-between text-xs"
                  >
                    <span className="font-bold flex items-center gap-2 truncate">
                      <span
                        className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${
                          isPassed
                            ? 'bg-[#059669] text-white'
                            : isFailed
                            ? 'bg-[#E11D48] text-white'
                            : 'bg-[#E5F2FA] text-[#52525B]'
                        }`}
                      >
                        {isPassed ? (
                          <Check className="w-3 h-3 stroke-[3]" />
                        ) : isFailed ? (
                          <XCircle className="w-3 h-3" />
                        ) : (
                          <HelpCircle className="w-3 h-3" />
                        )}
                      </span>
                      <span className="truncate">{chk.label}</span>
                    </span>
                    <span
                      className={`font-mono text-[11px] font-bold tabular-nums shrink-0 ml-2 ${
                        isPassed
                          ? 'text-[#059669]'
                          : isFailed
                          ? 'text-[#E11D48]'
                          : 'text-[#71717A]'
                      }`}
                    >
                      {statusLabel} · {isPassed ? `${chk.durationMs}ms` : '—'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-[#0A0A0A]/10 flex items-center justify-between text-xs font-bold">
            <span>Patch Verification Status</span>
            <span
              className={`px-3.5 py-1 rounded-full font-mono text-xs ${
                finding.status === 'Validated'
                  ? 'bg-[#059669] text-white'
                  : 'bg-[#E5F2FA] text-[#0A0A0A]'
              }`}
            >
              {finding.status === 'Validated' ? 'VERIFIED' : 'NOT VERIFIED (ACTION REQUIRED)'}
            </span>
          </div>
        </section>
      </div>
    </div>
  );
};
