import React, { useState } from 'react';
import {
  GitBranch,
  Clock,
  Plus,
  ArrowUpRight,
  Search,
} from 'lucide-react';
import { ScanRecord, NavigationTab } from '../types/security';

interface ScanHistoryViewProps {
  scans: ScanRecord[];
  onNavigateTab: (tab: NavigationTab) => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  scans,
  onNavigateTab,
}) => {
  const [statusFilter, setStatusFilter] = useState<'ALL' | ScanRecord['status']>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');

  const filteredScans = scans.filter((scan) => {
    if (statusFilter !== 'ALL' && scan.status !== statusFilter) return false;
    if (searchQuery.trim().length > 0) {
      const q = searchQuery.trim().toLowerCase();
      const hay = `${scan.id} ${scan.repository} ${scan.branch} ${scan.commitHash} ${scan.triggeredBy}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const activeScan =
    filteredScans.find((s) => s.id === selectedScanId) ||
    filteredScans[0] ||
    scans[0];

  if (scans.length === 0) {
    return (
      <div className="bg-white text-[#0A0A0A] rounded-[30px] p-10 text-center shadow-sm border border-black/5">
        <div className="max-w-md mx-auto py-8">
          <div className="w-16 h-16 rounded-full bg-[#E5F2FA] text-[#0A0A0A] flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 opacity-70" />
          </div>
          <h2 className="text-2xl font-extrabold tracking-tight text-[#0A0A0A]">
            No scan history available.
          </h2>
          <p className="text-xs text-[#52525B] mt-2 leading-relaxed">
            Run your first static analysis scan to record scan telemetry, vulnerability density, and validation audits in SQLite.
          </p>
          <button
            type="button"
            onClick={() => onNavigateTab('new-scan')}
            className="mt-6 px-7 py-3.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors cursor-pointer inline-flex items-center gap-2"
          >
            <span>Launch New Scan</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  const getStatusCapsuleStyle = (status: ScanRecord['status']) => {
    switch (status) {
      case 'SYNTAX VERIFIED':
        return 'bg-[#D8ECF8] text-[#0A0A0A]';
      case '0 REGRESSIONS':
        return 'bg-[#059669] text-white';
      case 'ACTION REQUIRED':
      default:
        return 'bg-[#E11D48] text-white';
    }
  };

  return (
    <div className="space-y-5">
      {/* Header & Filter Bar */}
      <section className="bg-white text-[#0A0A0A] rounded-[30px] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight leading-none">
              Repository Scan Ledger
            </h1>
            <p className="text-xs text-[#52525B] mt-1.5">
              Immutable audit log of deterministic AST scans, branch commit hashes, and automated patch verifications.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-[#71717A] absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                aria-label="Search scan history"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter repo, branch, commit..."
                className="w-full pl-10 pr-4 py-2 rounded-full bg-[#E5F2FA] text-xs font-medium text-[#0A0A0A] placeholder:text-[#52525B] focus:outline-none focus:ring-2 focus:ring-[#0A0A0A]"
              />
            </div>

            <button
              type="button"
              onClick={() => onNavigateTab('new-scan')}
              className="px-5 py-2.5 rounded-full bg-[#0A0A0A] text-white text-xs font-bold hover:bg-[#27272A] transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Trigger New Scan</span>
            </button>
          </div>
        </div>

        {/* Status Capsule Filter Pills */}
        <div className="mt-5 pt-4 border-t border-[#0A0A0A]/10 flex flex-wrap items-center gap-2">
          {(['ALL', 'SYNTAX VERIFIED', '0 REGRESSIONS', 'ACTION REQUIRED'] as const).map(
            (st) => {
              const active = statusFilter === st;
              return (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={`px-4 py-1.5 rounded-full text-xs font-bold transition-colors cursor-pointer ${
                    active
                      ? 'bg-[#0A0A0A] text-white'
                      : 'bg-[#E5F2FA] text-[#0A0A0A] hover:bg-[#CBE3F5]'
                  }`}
                >
                  {st}
                </button>
              );
            }
          )}
        </div>
      </section>

      {/* Architectural Rows + Selected Scan Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <div className="lg:col-span-8 space-y-3">
          {filteredScans.map((scan) => {
            const isSelected = activeScan?.id === scan.id;
            return (
              <div
                key={scan.id}
                onClick={() => setSelectedScanId(scan.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedScanId(scan.id);
                  }
                }}
                className={`rounded-[26px] p-5 transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-[#0A0A0A] text-white'
                    : 'bg-white text-[#0A0A0A] hover:bg-[#F8FBFE]'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-3 py-1.5 rounded-full font-mono text-xs font-extrabold ${
                        isSelected
                          ? 'bg-[#D8ECF8] text-[#0A0A0A]'
                          : 'bg-[#0A0A0A] text-white'
                      }`}
                    >
                      {scan.id}
                    </span>
                    <div>
                      <h2 className="text-base font-bold tracking-tight">
                        {scan.repository}
                      </h2>
                      <span
                        className={`text-xs ${
                          isSelected ? 'text-[#A1A1AA]' : 'text-[#52525B]'
                        }`}
                      >
                        {scan.engineProfile} · Triggered by {scan.triggeredBy}
                      </span>
                    </div>
                  </div>

                  <span
                    className={`px-3.5 py-1 rounded-full text-[11px] font-extrabold font-mono ${getStatusCapsuleStyle(
                      scan.status
                    )}`}
                  >
                    {scan.status}
                  </span>
                </div>

                {/* Pill-shaped Timestamp, Branch, Commit & AST Node Indicators */}
                <div className="mt-4 pt-3 border-t border-current/10 flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-mono text-[11px] font-semibold ${
                        isSelected
                          ? 'bg-white/10 text-[#D8ECF8]'
                          : 'bg-[#E5F2FA] text-[#0A0A0A]'
                      }`}
                    >
                      <GitBranch className="w-3 h-3" />
                      <span>{scan.branch}</span>
                      <span>({scan.commitHash})</span>
                    </span>

                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-mono text-[11px] tabular-nums ${
                        isSelected
                          ? 'bg-white/10 text-white'
                          : 'bg-[#F4F8FB] text-[#52525B]'
                      }`}
                    >
                      <Clock className="w-3 h-3" />
                      <span>{scan.timestamp}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[11px] tabular-nums">
                    <span className="px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] font-bold">
                      {scan.astNodesInspected} AST nodes
                    </span>
                    <span
                      className={`px-3 py-1 rounded-full font-bold ${
                        isSelected
                          ? 'bg-white text-[#0A0A0A]'
                          : 'bg-[#0A0A0A] text-white'
                      }`}
                    >
                      {scan.duration}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Selected Scan Architectural Summary Card */}
        {activeScan && (
          <div className="lg:col-span-4 bg-[#0A0A0A] text-white rounded-[30px] p-6 space-y-5 sticky top-4">
            <div className="flex items-center justify-between">
              <span className="px-3 py-1 rounded-full bg-[#D8ECF8] text-[#0A0A0A] font-mono text-xs font-extrabold">
                {activeScan.id} REPORT
              </span>
              <span className="font-mono text-xs text-[#A1A1AA] tabular-nums">
                {activeScan.duration}
              </span>
            </div>

            <div>
              <h3 className="text-2xl font-bold tracking-tight">
                {activeScan.repository}
              </h3>
              <p className="text-xs text-[#A1A1AA] mt-1 font-mono">
                Branch: {activeScan.branch} · Commit #{activeScan.commitHash}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[#18181B] border border-white/10 rounded-[20px] p-4">
                <div className="text-2xl font-extrabold font-mono tabular-nums text-white">
                  {activeScan.totalFilesScanned}
                </div>
                <div className="text-[11px] text-[#A1A1AA] mt-0.5">
                  Source Files Parsed
                </div>
              </div>
              <div className="bg-[#D8ECF8] text-[#0A0A0A] rounded-[20px] p-4">
                <div className="text-2xl font-extrabold font-mono tabular-nums">
                  {activeScan.autoPatchedCount}
                </div>
                <div className="text-[11px] font-semibold text-[#0A0A0A]/75 mt-0.5">
                  Auto-Synthesized Patches
                </div>
              </div>
            </div>

            <div className="bg-[#18181B] rounded-[22px] p-4 space-y-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#A1A1AA]">AST Nodes Inspected</span>
                <span className="font-mono font-bold tabular-nums">
                  {activeScan.astNodesInspected}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#A1A1AA]">Critical Sinks</span>
                <span className="px-2.5 py-0.5 rounded-full bg-[#E11D48] text-white font-mono font-bold tabular-nums">
                  {activeScan.criticalCount}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#A1A1AA]">High Severity Sinks</span>
                <span className="px-2.5 py-0.5 rounded-full bg-[#D97706] text-white font-mono font-bold tabular-nums">
                  {activeScan.highCount}
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onNavigateTab('vulnerabilities')}
              className="w-full py-3.5 px-5 rounded-full bg-white text-[#0A0A0A] text-xs font-extrabold hover:bg-[#D8ECF8] transition-colors flex items-center justify-center gap-2 cursor-pointer"
            >
              <span>Inspect Discovered Sinks</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
