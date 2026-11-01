import React from 'react';
import {
  LayoutGrid,
  ScanSearch,
  ShieldAlert,
  Wrench,
  FlaskConical,
  History,
  ArrowUpRight,
  Cpu,
  Sparkles,
} from 'lucide-react';
import { NavigationTab, SecurityPostureMetrics } from '../types/security';

interface SidebarProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  metrics: SecurityPostureMetrics;
}

const NAV_ITEMS: {
  id: NavigationTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badgeKey?: 'open' | 'fixable';
}[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert, badgeKey: 'open' },
  { id: 'remediation', label: 'Remediation', icon: Wrench, badgeKey: 'fixable' },
  { id: 'validation-lab', label: 'Validation Lab', icon: FlaskConical },
  { id: 'scan-history', label: 'Scan History', icon: History },
  { id: 'new-scan', label: 'New AST Scan', icon: ScanSearch },
  { id: 'iot-analyzer', label: 'IoT Firmware Security', icon: Cpu },
  { id: 'firmware-synthesis', label: 'Firmware Synthesis', icon: Sparkles },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  metrics,
}) => {
  const openCount = metrics.totalFindings - metrics.validatedCount;

  return (
    <aside
      aria-label="Primary Sidebar Navigation"
      className="w-full lg:w-[268px] shrink-0 bg-[#0A0A0A] text-white rounded-[30px] p-5 flex flex-col justify-between lg:min-h-[calc(100vh-2.5rem)] select-none"
    >
      <div>
        {/* Brand Identity matching reference 4-petal geometric mark */}
        <div className="flex items-center justify-between px-2 pt-1 pb-6 border-b border-white/10">
          <button
            type="button"
            onClick={() => onSelectTab('overview')}
            className="flex items-center gap-3 text-left group focus:outline-none cursor-pointer"
          >
            <span className="w-9 h-9 rounded-full bg-[#D8ECF8] text-[#0A0A0A] flex items-center justify-center shrink-0 transition-transform duration-200 group-hover:scale-105">
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <circle cx="8" cy="8" r="4.2" />
                <circle cx="16" cy="8" r="4.2" />
                <circle cx="8" cy="16" r="4.2" />
                <circle cx="16" cy="16" r="4.2" />
              </svg>
            </span>
            <div>
              <span className="block text-base font-extrabold tracking-tight text-white leading-none">
                VULNEX
              </span>
              <span className="block text-[11px] text-[#A1A1AA] mt-1 font-medium">
                AST Security Studio
              </span>
            </div>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('new-scan')}
            aria-label="Quick launch New AST Scan"
            className="w-8 h-8 rounded-full border border-white/20 flex items-center justify-center text-white/80 hover:bg-[#D8ECF8] hover:text-[#0A0A0A] hover:border-[#D8ECF8] transition-colors cursor-pointer"
          >
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Links */}
        <nav aria-label="Workspace Views" className="mt-6 space-y-1.5">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            const countValue =
              item.badgeKey === 'open'
                ? openCount
                : item.badgeKey === 'fixable'
                ? metrics.autoFixableCount
                : null;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`relative w-full flex items-center justify-between px-4 py-3 rounded-full text-sm font-semibold transition-all duration-150 cursor-pointer whitespace-nowrap ${
                  isActive
                    ? 'bg-[#D8ECF8] text-[#0A0A0A]'
                    : 'text-[#A1A1AA] hover:text-white hover:bg-white/5'
                }`}
              >
                <span className="relative z-10 flex items-center gap-3">
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </span>
                {countValue !== null && (
                  <span
                    className={`relative z-10 text-xs font-mono tabular-nums px-2 py-0.5 rounded-full ${
                      isActive
                        ? 'bg-[#0A0A0A] text-white'
                        : 'bg-white/10 text-white/80'
                    }`}
                  >
                    {countValue}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Architectural Posture Module */}
      <div className="mt-8 bg-[#D8ECF8] text-[#0A0A0A] rounded-[24px] p-4">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-bold tracking-tight text-[#0A0A0A]/70 uppercase">
            Security Analysis Overview
          </span>
          <button
            type="button"
            onClick={() => onSelectTab('overview')}
            aria-label="Inspect Overview"
            className="w-7 h-7 rounded-full border border-[#0A0A0A]/20 flex items-center justify-center text-[#0A0A0A] hover:bg-[#0A0A0A] hover:text-white transition-colors cursor-pointer"
          >
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-extrabold tracking-tight tabular-nums">
            {metrics.totalScans}
          </span>
          <span className="text-xs font-semibold text-[#0A0A0A]/70">
            {metrics.totalScans === 1 ? 'scan executed' : 'scans executed'}
          </span>
        </div>

        <p className="mt-2 text-xs text-[#0A0A0A]/75 leading-relaxed">
          {metrics.totalScans === 0
            ? 'Awaiting source code submission. Submit code to generate telemetry.'
            : `${metrics.validatedCount} of ${metrics.totalFindings} findings verified safe (${metrics.totalLinesAnalyzed} LOC analyzed).`}
        </p>

        <div className="mt-3 pt-3 border-t border-[#0A0A0A]/10 flex items-center justify-between text-[11px] font-semibold">
          <span className="text-[#0A0A0A]/60">Vulnerability Density</span>
          <span className="font-mono text-[#0A0A0A] font-bold">
            {metrics.vulnerabilityDensity > 0 ? `${metrics.vulnerabilityDensity}%` : '0%'}
          </span>
        </div>
      </div>
    </aside>
  );
};
