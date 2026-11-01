import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Cpu,
  FileCode,
  ShieldCheck,
  Download,
  Copy,
  Check,
  Layers,
  Terminal,
  Settings,
  AlertCircle,
  Loader2,
  Bookmark,
  RefreshCw,
} from 'lucide-react';
import {
  FirmwareSynthesisResponse,
  FirmwareTemplate,
  NavigationTab,
} from '../types/security';
import { apiClient } from '../services/apiClient';

interface FirmwareSynthesisViewProps {
  onNavigateTab: (tab: NavigationTab) => void;
}

const PLATFORMS = [
  { id: 'esp32', name: 'ESP32 (ESP-IDF)', rtos: 'FreeRTOS' },
  { id: 'stm32', name: 'STM32 (HAL / LL)', rtos: 'FreeRTOS' },
  { id: 'arduino', name: 'Arduino / ESP8266', rtos: 'None' },
  { id: 'arm_cortex', name: 'ARM Cortex-M', rtos: 'CMSIS-RTOS' },
  { id: 'freertos', name: 'Generic FreeRTOS', rtos: 'FreeRTOS' },
  { id: 'zephyr', name: 'Zephyr RTOS', rtos: 'Zephyr' },
];

export const FirmwareSynthesisView: React.FC<FirmwareSynthesisViewProps> = ({
  onNavigateTab,
}) => {
  const [targetPlatform, setTargetPlatform] = useState<string>('esp32');
  const [rtos, setRtos] = useState<string>('FreeRTOS');
  const [componentType, setComponentType] = useState<string>('communication');
  const [requirementPrompt, setRequirementPrompt] = useState<string>('');
  const [templates, setTemplates] = useState<FirmwareTemplate[]>([]);
  const [isSynthesizing, setIsSynthesizing] = useState<boolean>(false);
  const [synthesisResult, setSynthesisResult] = useState<FirmwareSynthesisResponse | null>(null);
  const [activeCodeTab, setActiveCodeTab] = useState<'source' | 'header' | 'config' | 'security' | 'tests'>('source');
  const [copiedTab, setCopiedTab] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load curated templates on mount
  useEffect(() => {
    apiClient
      .getFirmwareTemplates()
      .then((data) => setTemplates(data))
      .catch(() => {});
  }, []);

  const handleSelectTemplate = (tmpl: FirmwareTemplate) => {
    setTargetPlatform(tmpl.target_platform);
    const plat = PLATFORMS.find((p) => p.id === tmpl.target_platform);
    if (plat) setRtos(plat.rtos);
    setComponentType(tmpl.category);
    setRequirementPrompt(tmpl.sample_prompt);
    setErrorMessage(null);
  };

  const handleSynthesize = async () => {
    if (!requirementPrompt.trim()) {
      setErrorMessage('Please describe the required firmware component behavior and security guarantees.');
      return;
    }

    setIsSynthesizing(true);
    setErrorMessage(null);

    try {
      const res = await apiClient.synthesizeFirmware({
        target_platform: targetPlatform,
        rtos,
        requirement: requirementPrompt,
        component_type: componentType,
      });
      setSynthesisResult(res);
      setActiveCodeTab('source');
    } catch (err: any) {
      setErrorMessage(err.message || 'Firmware synthesis failed. Please try again.');
    } finally {
      setIsSynthesizing(false);
    }
  };

  const handleCopy = (text: string, tabName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(tabName);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0A0A0A] text-white rounded-[32px] p-8 border border-white/10 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#D8ECF8]/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#D8ECF8]/15 border border-[#D8ECF8]/30 text-[#D8ECF8] text-xs font-semibold uppercase tracking-wider mb-3">
            <Sparkles className="w-3.5 h-3.5" />
            AI Secure Software Synthesis Engine
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight">
            Secure IoT Firmware Synthesizer
          </h1>
          <p className="text-sm text-[#A1A1AA] mt-2 max-w-2xl leading-relaxed">
            Generate production-grade, memory-safe, hardened C/C++ firmware components with complete headers, sdkconfig files, unit tests, and cryptographic verification for ESP32, STM32, and FreeRTOS.
          </p>
        </div>
      </div>

      {/* Synthesis Configuration Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Hardware & Framework Selectors */}
        <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-4">
          <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider">
            Hardware & Target RTOS
          </h3>

          <div>
            <label className="block text-xs font-bold text-zinc-700 mb-1.5">
              Target Microcontroller
            </label>
            <select
              value={targetPlatform}
              onChange={(e) => {
                setTargetPlatform(e.target.value);
                const plat = PLATFORMS.find((p) => p.id === e.target.value);
                if (plat) setRtos(plat.rtos);
              }}
              className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-3.5 py-2.5 text-xs font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8]"
            >
              {PLATFORMS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-bold text-zinc-700 mb-1.5">
              Operating System / RTOS
            </label>
            <input
              type="text"
              value={rtos}
              onChange={(e) => setRtos(e.target.value)}
              className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-3.5 py-2.5 text-xs font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8]"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-zinc-700 mb-1.5">
              Component Domain
            </label>
            <select
              value={componentType}
              onChange={(e) => setComponentType(e.target.value)}
              className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-3.5 py-2.5 text-xs font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8]"
            >
              <option value="communication">Secure Communication (TLS/MQTT/HTTPS)</option>
              <option value="ota_update">Cryptographic OTA Firmware Updater</option>
              <option value="system_watchdog">FreeRTOS Task Watchdog & Stack Canary</option>
              <option value="memory">DMA Safe Ring Buffer (STM32 HAL)</option>
              <option value="device_auth">Encrypted Storage / NVS Master Key</option>
            </select>
          </div>
        </div>

        {/* Curated One-Click Templates */}
        <div className="lg:col-span-2 bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider">
              High-Assurance Component Templates
            </h3>
            <span className="text-xs text-zinc-400">Click to autofill requirement</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {templates.map((tmpl) => (
              <button
                type="button"
                key={tmpl.id}
                onClick={() => handleSelectTemplate(tmpl)}
                className="p-4 rounded-2xl border border-zinc-200/80 bg-zinc-50/50 hover:bg-[#D8ECF8]/20 hover:border-[#D8ECF8] text-left transition-all cursor-pointer group space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full bg-zinc-200/70 text-zinc-800">
                    {tmpl.target_platform.toUpperCase()}
                  </span>
                  <Bookmark className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-800 transition-colors" />
                </div>
                <div className="text-xs font-bold text-zinc-900">{tmpl.title}</div>
                <p className="text-[11px] text-zinc-500 leading-snug line-clamp-2">
                  {tmpl.description}
                </p>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Requirement Input Area */}
      <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-4">
        <label className="block text-xs font-bold text-zinc-500 uppercase tracking-wider">
          Synthesis Requirement Specification
        </label>
        <textarea
          value={requirementPrompt}
          onChange={(e) => {
            setRequirementPrompt(e.target.value);
            setErrorMessage(null);
          }}
          placeholder="Describe your security requirements in natural language...&#10;e.g. Generate a secure MQTT telemetry client for ESP32 with X.509 root certificate verification, TLS session resumption, and FreeRTOS task stack protection."
          rows={4}
          className="w-full bg-zinc-50 border border-zinc-200 rounded-2xl p-4 text-xs font-medium text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#0A0A0A] leading-relaxed resize-y"
        />

        {errorMessage && (
          <div className="flex items-center gap-2.5 p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-zinc-400">
            Synthesizes memory-safe C/C++ code, header, configuration, and unit tests
          </span>
          <button
            type="button"
            onClick={handleSynthesize}
            disabled={isSynthesizing || !requirementPrompt.trim()}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-[#0A0A0A] text-white text-xs font-extrabold uppercase tracking-wider hover:bg-zinc-800 disabled:opacity-50 transition-all cursor-pointer shadow-sm"
          >
            {isSynthesizing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-[#D8ECF8]" />
                Synthesizing Firmware Component...
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-[#D8ECF8]" />
                Synthesize Secure Component
              </>
            )}
          </button>
        </div>
      </div>

      {/* Synthesized Artifact Output Section */}
      {synthesisResult && (
        <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-100">
            <div>
              <div className="inline-flex items-center gap-1.5 text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full uppercase tracking-wider mb-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                Synthesized Secure Component
              </div>
              <h2 className="text-xl font-extrabold text-zinc-900">
                {synthesisResult.title || 'Secure Firmware Module'}
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Target: {synthesisResult.target_platform.toUpperCase()} · RTOS: {synthesisResult.rtos || 'FreeRTOS'}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  let content = synthesisResult.source_code;
                  let ext = synthesisResult.target_platform === 'arduino' ? 'cpp' : 'c';
                  if (activeCodeTab === 'header') {
                    content = synthesisResult.header_code;
                    ext = 'h';
                  } else if (activeCodeTab === 'config') {
                    content = synthesisResult.configuration_file || '';
                    ext = 'txt';
                  } else if (activeCodeTab === 'tests') {
                    content = synthesisResult.unit_tests || '';
                    ext = 'c';
                  }
                  handleDownloadFile(`secure_component.${ext}`, content);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-zinc-200 text-xs font-bold text-zinc-700 hover:bg-zinc-50 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Download Current
              </button>
            </div>
          </div>

          {/* Navigation Code Tabs */}
          <div className="flex flex-wrap items-center gap-2 border-b border-zinc-200 pb-2">
            {[
              { id: 'source', label: `Source Code (.${synthesisResult.target_platform === 'arduino' ? 'cpp' : 'c'})`, icon: FileCode },
              { id: 'header', label: 'Header (.h)', icon: Layers },
              { id: 'config', label: 'Config / Build (sdkconfig)', icon: Settings },
              { id: 'security', label: 'Security Considerations', icon: ShieldCheck },
              { id: 'tests', label: 'Unit Tests (Unity/CppUTest)', icon: Terminal },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeCodeTab === tab.id;
              return (
                <button
                  type="button"
                  key={tab.id}
                  onClick={() => setActiveCodeTab(tab.id as any)}
                  className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    isActive
                      ? 'bg-[#0A0A0A] text-white shadow-sm'
                      : 'text-zinc-600 hover:text-zinc-900 hover:bg-zinc-100'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Tab Contents */}
          <div className="relative">
            {activeCodeTab === 'source' && (
              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs text-zinc-500">
                  <span className="font-mono">
                    secure_component.{synthesisResult.target_platform === 'arduino' ? 'cpp' : 'c'}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy(synthesisResult.source_code, 'source')}
                    className="inline-flex items-center gap-1 text-zinc-700 hover:text-zinc-900 font-bold"
                  >
                    {copiedTab === 'source' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedTab === 'source' ? 'Copied!' : 'Copy Code'}
                  </button>
                </div>
                <pre className="bg-[#0A0A0A] text-emerald-300 font-mono text-xs p-5 rounded-2xl overflow-x-auto leading-relaxed border border-zinc-800">
                  {synthesisResult.source_code}
                </pre>
              </div>
            )}

            {activeCodeTab === 'header' && (
              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs text-zinc-500">
                  <span className="font-mono">secure_component.h</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(synthesisResult.header_code, 'header')}
                    className="inline-flex items-center gap-1 text-zinc-700 hover:text-zinc-900 font-bold"
                  >
                    {copiedTab === 'header' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedTab === 'header' ? 'Copied!' : 'Copy Header'}
                  </button>
                </div>
                <pre className="bg-[#0A0A0A] text-cyan-300 font-mono text-xs p-5 rounded-2xl overflow-x-auto leading-relaxed border border-zinc-800">
                  {synthesisResult.header_code}
                </pre>
              </div>
            )}

            {activeCodeTab === 'config' && (
              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs text-zinc-500">
                  <span className="font-mono">sdkconfig / CMakeLists.txt</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(synthesisResult.configuration_file || '', 'config')}
                    className="inline-flex items-center gap-1 text-zinc-700 hover:text-zinc-900 font-bold"
                  >
                    {copiedTab === 'config' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedTab === 'config' ? 'Copied!' : 'Copy Config'}
                  </button>
                </div>
                <pre className="bg-[#0A0A0A] text-amber-200 font-mono text-xs p-5 rounded-2xl overflow-x-auto leading-relaxed border border-zinc-800">
                  {synthesisResult.configuration_file || '# No configuration required for bare-metal component'}
                </pre>
              </div>
            )}

            {activeCodeTab === 'security' && (
              <div className="space-y-4">
                <div className="bg-emerald-50/70 border border-emerald-200 rounded-2xl p-5 space-y-3">
                  <h4 className="text-sm font-extrabold text-emerald-950 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Formal Security Assurances & Guarantees
                  </h4>
                  <ul className="space-y-2">
                    {synthesisResult.security_considerations.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2.5 text-xs text-emerald-900">
                        <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {synthesisResult.dependencies && synthesisResult.dependencies.length > 0 && (
                  <div className="p-4 rounded-2xl bg-zinc-50 border border-zinc-200 text-xs space-y-1.5">
                    <span className="font-bold text-zinc-700 block">Required Dependencies & SDK Components:</span>
                    <div className="flex flex-wrap gap-2">
                      {synthesisResult.dependencies.map((dep, idx) => (
                        <span key={idx} className="px-2.5 py-1 rounded-lg bg-zinc-200/80 font-mono text-[11px] text-zinc-800 font-semibold">
                          {dep}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeCodeTab === 'tests' && (
              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs text-zinc-500">
                  <span className="font-mono">test_secure_component.c</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(synthesisResult.unit_tests || '', 'tests')}
                    className="inline-flex items-center gap-1 text-zinc-700 hover:text-zinc-900 font-bold"
                  >
                    {copiedTab === 'tests' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedTab === 'tests' ? 'Copied!' : 'Copy Tests'}
                  </button>
                </div>
                <pre className="bg-[#0A0A0A] text-zinc-200 font-mono text-xs p-5 rounded-2xl overflow-x-auto leading-relaxed border border-zinc-800">
                  {synthesisResult.unit_tests || '// No unit tests generated'}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
