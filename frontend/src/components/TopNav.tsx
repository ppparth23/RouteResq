import React from 'react';
import { NavigationTab } from '../types/security';
import { RotateCcw, Activity } from 'lucide-react';

interface TopNavProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  isBackendOnline?: boolean;
  onResetDemo?: () => void;
}

const VIEW_LABELS: Record<NavigationTab, string> = {
  overview: 'Security Posture & Patch Velocity',
  vulnerabilities: 'Vulnerability Findings',
  remediation: 'AST Remediation Workbench',
  'validation-lab': 'Sandbox Validation Lab',
  'scan-history': 'Repository Scan Ledger',
  'new-scan': 'Configure AST Scan',
  'iot-analyzer': 'IoT Firmware Security',
  'firmware-synthesis': 'Secure Firmware Synthesis',
};

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  onSelectTab,
  isBackendOnline = true,
  onResetDemo,
}) => {
  return (
    <header className="flex items-center justify-between gap-6 px-6 py-4 bg-white rounded-[28px] mb-5 shadow-sm">
      {/* Zone 1: Wordmark / Breadcrumb */}
      <a
        href="#overview"
        onClick={(e) => {
          e.preventDefault();
          onSelectTab('overview');
        }}
        className="text-base font-extrabold tracking-tight text-[#0A0A0A] whitespace-nowrap shrink-0 flex items-center gap-2"
      >
        <span>VULNEX</span>
        <span className="text-[#A1A1AA]">/</span>
        <span className="text-[#52525B] font-semibold">{VIEW_LABELS[activeTab]}</span>
      </a>

      {/* Zone 2: Live Status & Actions */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Backend Online Pill */}
        <div
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-bold font-mono ${
            isBackendOnline
              ? 'bg-[#E5F7ED] text-[#059669]'
              : 'bg-[#FFEBEB] text-[#E11D48]'
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isBackendOnline ? 'bg-[#059669] animate-pulse' : 'bg-[#E11D48]'
            }`}
          />
          <span>{isBackendOnline ? 'API ONLINE' : 'API OFFLINE'}</span>
        </div>

        {/* Reset Demo Button */}
        {onResetDemo && (
          <button
            type="button"
            onClick={onResetDemo}
            title="Reset demonstration state"
            className="p-2 text-xs font-bold text-[#52525B] hover:text-[#0A0A0A] bg-[#E5F2FA] hover:bg-[#D8ECF8] rounded-full transition-colors cursor-pointer flex items-center justify-center"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        )}

        <button
          type="button"
          onClick={() => onSelectTab('new-scan')}
          className="px-5 py-2.5 text-xs font-bold text-white bg-[#0A0A0A] rounded-full hover:bg-[#27272A] transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-sm"
        >
          Launch AST Scan
        </button>
      </div>
    </header>
  );
};
