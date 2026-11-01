import React, { useState, useEffect, useRef } from 'react';
import {
  Cpu,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Wifi,
  RefreshCw,
  Code2,
  Terminal,
  Upload,
  Trash2,
  Loader2,
  ArrowRight,
  ExternalLink,
  Layers,
  Sparkles,
} from 'lucide-react';
import {
  FirmwareAnalysisResponse,
  NavigationTab,
  VulnerabilityFinding,
} from '../types/security';
import { apiClient } from '../services/apiClient';

interface IoTAnalyzerViewProps {
  onNavigateTab: (tab: NavigationTab) => void;
  onInspectFinding: (findingId: string) => void;
  onSendToRemediation?: (finding: VulnerabilityFinding) => void;
}

const PLATFORMS = [
  { id: 'esp32', name: 'ESP32 (ESP-IDF)', rtos: 'FreeRTOS' },
  { id: 'stm32', name: 'STM32 (HAL / LL)', rtos: 'FreeRTOS' },
  { id: 'arduino', name: 'Arduino / ESP8266', rtos: 'None' },
  { id: 'arm_cortex', name: 'ARM Cortex-M', rtos: 'CMSIS-RTOS' },
  { id: 'freertos', name: 'Generic FreeRTOS', rtos: 'FreeRTOS' },
  { id: 'zephyr', name: 'Zephyr RTOS', rtos: 'Zephyr' },
  { id: 'rp2040', name: 'RP2040 / Pico', rtos: 'FreeRTOS' },
  { id: 'generic', name: 'Embedded C/C++', rtos: 'None' },
];

const SECURITY_DOMAINS = [
  { id: 'memory', label: 'Memory Safety', desc: 'Buffer overflows, UAF, double free, memory leaks' },
  { id: 'communication', label: 'Communication Security', desc: 'Plaintext MQTT, HTTP, disabled TLS verification' },
  { id: 'ota_update', label: 'Firmware Update / OTA', desc: 'Unsigned OTA binaries, rollback protection' },
  { id: 'device_auth', label: 'Device Authentication', desc: 'Hardcoded Wi-Fi PSK, API keys, credentials' },
  { id: 'embedded_system', label: 'System Security', desc: 'FreeRTOS task stack depth, UART debug leaks' },
];

const SAMPLES = [
  {
    label: 'Select vulnerable IoT sample...',
    platform: 'esp32',
    code: '',
  },
  {
    label: 'ESP32 Plaintext MQTT Telemetry (CWE-319)',
    platform: 'esp32',
    code: `#include <stdio.h>
#include "esp_log.h"
#include "mqtt_client.h"

static const char *TAG = "IOT_TELEMETRY";

void init_telemetry_client() {
    // VULNERABILITY: Plaintext unencrypted MQTT (CWE-319)
    // Sensitive telemetry and actuator commands transmitted in cleartext
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = "mqtt://broker.hivemq.com:1883",
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_start(client);
    ESP_LOGI(TAG, "Connected to unencrypted MQTT broker!");
}
`,
  },
  {
    label: 'ESP32 Unsigned OTA Firmware Update (CWE-494)',
    platform: 'esp32',
    code: `#include <stdio.h>
#include "esp_ota_ops.h"
#include "esp_log.h"

static const char *TAG = "OTA_HANDLER";

void flash_remote_update(const esp_partition_t *update_partition) {
    esp_ota_handle_t update_handle = 0;
    
    // VULNERABILITY: Unsigned OTA update without cryptographic verification (CWE-494)
    // No signature check or hash verification before committing binary
    esp_err_t err = esp_ota_begin(update_partition, 0, &update_handle);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OTA partition flashed without cryptographic verification!");
    }
}
`,
  },
  {
    label: 'Arduino TLS Verification Bypass setInsecure() (CWE-295)',
    platform: 'arduino',
    code: `#include <WiFiClientSecure.h>

WiFiClientSecure client;

void connect_to_cloud() {
    // VULNERABILITY: Disabling X.509 certificate validation (CWE-295)
    // Enables trivial Man-In-The-Middle (MITM) attacks and credential theft
    client.setInsecure();
    
    if (client.connect("api.iotcloud.com", 443)) {
        client.println("POST /telemetry HTTP/1.1");
    }
}
`,
  },
  {
    label: 'Hardcoded Wi-Fi Credentials & Stack Overflow (CWE-798 & CWE-121)',
    platform: 'esp32',
    code: `#include <stdio.h>
#include <string.h>

// VULNERABILITY: Hardcoded network credentials in firmware binary (CWE-798)
static const char *DEFAULT_SSID = "OfficeInternalWiFi";
static const char *DEFAULT_PSK = "CompanySecretWiFiPassword2026!";

void parse_packet(const char *incoming_payload) {
    char local_buffer[32];
    // VULNERABILITY: Stack buffer overflow (CWE-121)
    strcpy(local_buffer, incoming_payload);
    printf("Processed payload: %s\\n", local_buffer);
}
`,
  },
];

export const IoTAnalyzerView: React.FC<IoTAnalyzerViewProps> = ({
  onNavigateTab,
  onInspectFinding,
  onSendToRemediation,
}) => {
  const [targetPlatform, setTargetPlatform] = useState<string>('esp32');
  const [rtos, setRtos] = useState<string>('FreeRTOS');
  const [selectedChecks, setSelectedChecks] = useState<string[]>([
    'memory',
    'communication',
    'ota_update',
    'device_auth',
    'embedded_system',
  ]);
  const [sourceCode, setSourceCode] = useState<string>('');
  const [filename, setFilename] = useState<string>('firmware_main.c');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<FirmwareAnalysisResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [toolStatus, setToolStatus] = useState<{ [tool: string]: any } | null>(null);

  // Refactoring state
  const [refactorFinding, setRefactorFinding] = useState<VulnerabilityFinding | null>(null);
  const [isRefactoring, setIsRefactoring] = useState<boolean>(false);
  const [refactorResult, setRefactorResult] = useState<any | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch host toolchain status on mount
  useEffect(() => {
    apiClient
      .getToolchainStatus()
      .then((status) => setToolStatus(status))
      .catch(() => {});
  }, []);

  const handleToggleCheck = (id: string) => {
    setSelectedChecks((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    );
  };

  const handleSelectSample = (idx: number) => {
    if (idx === 0) return;
    const sample = SAMPLES[idx];
    setSourceCode(sample.code);
    setTargetPlatform(sample.platform);
    const plat = PLATFORMS.find((p) => p.id === sample.platform);
    if (plat) setRtos(plat.rtos);
    setFilename(sample.platform === 'arduino' ? 'firmware.cpp' : 'firmware.c');
    setAnalysisResult(null);
    setErrorMessage(null);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setSourceCode((event.target?.result as string) || '');
      setFilename(file.name);
      setAnalysisResult(null);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleRunAnalysis = async () => {
    if (!sourceCode.trim()) {
      setErrorMessage('Please enter or upload C/C++ firmware source code before analyzing.');
      return;
    }

    setIsAnalyzing(true);
    setErrorMessage(null);
    setAnalysisResult(null);

    try {
      const res = await apiClient.analyzeFirmware({
        source_code: sourceCode,
        filename,
        target_platform: targetPlatform,
        rtos,
        security_checks: selectedChecks,
      });
      setAnalysisResult(res);
    } catch (err: any) {
      setErrorMessage(err.message || 'Firmware security analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleTriggerRefactor = async (finding: VulnerabilityFinding) => {
    setRefactorFinding(finding);
    setIsRefactoring(true);
    setRefactorResult(null);

    try {
      const res = await apiClient.refactorFirmware({
        insecure_code: finding.vulnerableSnippet || sourceCode,
        vulnerability_type: finding.cwe || 'CWE-120',
        target_platform: targetPlatform,
      });
      setRefactorResult(res);
    } catch (err: any) {
      setRefactorResult({ error: err.message || 'Refactoring failed' });
    } finally {
      setIsRefactoring(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0A0A0A] text-white rounded-[32px] p-8 border border-white/10 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#D8ECF8]/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#D8ECF8]/15 border border-[#D8ECF8]/30 text-[#D8ECF8] text-xs font-semibold uppercase tracking-wider mb-3">
              <Cpu className="w-3.5 h-3.5" />
              Embedded Hardware Security Module
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight">
              Secure IoT Firmware Analyzer
            </h1>
            <p className="text-sm text-[#A1A1AA] mt-2 max-w-2xl leading-relaxed">
              Detect memory safety bugs, plaintext IoT telemetry, unsigned OTA vulnerabilities, and credential leaks in embedded C/C++ projects targeting ESP32, STM32, ARM Cortex-M, and FreeRTOS.
            </p>
          </div>

          {/* Quick Toolchain Status Badge */}
          {toolStatus && (
            <div className="bg-white/5 border border-white/10 rounded-2xl p-4 shrink-0 text-xs font-mono space-y-1.5 min-w-[220px]">
              <div className="text-[11px] font-bold text-white/50 uppercase tracking-wider mb-1">
                Detected Toolchains
              </div>
              <div className="flex items-center justify-between">
                <span className="text-white/80">Semgrep AST:</span>
                <span className={toolStatus.semgrep?.available ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
                  {toolStatus.semgrep?.available ? 'ACTIVE (v1.183)' : 'UNAVAILABLE'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-white/80">Embedded AST:</span>
                <span className="text-emerald-400 font-semibold">ACTIVE</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-white/80">Host Clang:</span>
                <span className={toolStatus.clang?.available ? 'text-emerald-400' : 'text-white/40'}>
                  {toolStatus.clang?.available ? 'INSTALLED' : 'NOT RUN'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-white/80">ARM GCC:</span>
                <span className={toolStatus.arm_gcc?.available ? 'text-emerald-400' : 'text-white/40'}>
                  {toolStatus.arm_gcc?.available ? 'INSTALLED' : 'NOT RUN'}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Configuration & Target Platform Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Platform & RTOS Selector */}
        <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-5">
          <div>
            <label className="block text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">
              1. Target Platform & Architecture
            </label>
            <select
              value={targetPlatform}
              onChange={(e) => {
                setTargetPlatform(e.target.value);
                const found = PLATFORMS.find((p) => p.id === e.target.value);
                if (found) setRtos(found.rtos);
              }}
              className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-3.5 py-2.5 text-sm font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8]"
            >
              {PLATFORMS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">
              2. RTOS / Execution Environment
            </label>
            <input
              type="text"
              value={rtos}
              onChange={(e) => setRtos(e.target.value)}
              placeholder="e.g. FreeRTOS, Zephyr, None"
              className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-3.5 py-2.5 text-sm font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8]"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">
              3. Preset IoT Vulnerability Samples
            </label>
            <select
              onChange={(e) => handleSelectSample(Number(e.target.value))}
              defaultValue="0"
              className="w-full bg-[#D8ECF8]/30 border border-[#D8ECF8] rounded-xl px-3.5 py-2.5 text-sm font-semibold text-zinc-900 focus:outline-none focus:ring-2 focus:ring-[#0A0A0A]"
            >
              {SAMPLES.map((s, idx) => (
                <option key={idx} value={idx}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Right 2 Columns: Firmware Security Checklist */}
        <div className="lg:col-span-2 bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-4">
          <label className="block text-xs font-bold text-zinc-500 uppercase tracking-wider">
            Firmware Security Checks to Enforce
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {SECURITY_DOMAINS.map((domain) => {
              const checked = selectedChecks.includes(domain.id);
              return (
                <button
                  type="button"
                  key={domain.id}
                  onClick={() => handleToggleCheck(domain.id)}
                  className={`flex items-start gap-3 p-3.5 rounded-2xl border text-left transition-all ${
                    checked
                      ? 'bg-[#D8ECF8]/20 border-[#D8ECF8] shadow-sm'
                      : 'bg-zinc-50/50 border-zinc-200 hover:bg-zinc-100'
                  }`}
                >
                  <div
                    className={`w-5 h-5 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                      checked ? 'bg-[#0A0A0A] text-white' : 'border border-zinc-300'
                    }`}
                  >
                    {checked && <CheckCircle2 className="w-3.5 h-3.5" />}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-zinc-900">{domain.label}</div>
                    <div className="text-[11px] text-zinc-500 mt-0.5 leading-snug">
                      {domain.desc}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Code Editor Section */}
      <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-zinc-600" />
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="text-xs font-mono font-bold text-zinc-800 bg-zinc-100 px-3 py-1.5 rounded-lg border border-zinc-200 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
            <span className="text-xs text-zinc-400">
              ({sourceCode ? sourceCode.split('\n').length : 0} lines)
            </span>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".c,.cpp,.h,.hpp,.ino,.cc"
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-zinc-200 text-xs font-semibold text-zinc-700 hover:bg-zinc-50 transition-colors"
            >
              <Upload className="w-3.5 h-3.5" />
              Upload Source File
            </button>
            <button
              type="button"
              onClick={() => {
                setSourceCode('');
                setAnalysisResult(null);
                setErrorMessage(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-zinc-200 text-xs font-semibold text-red-600 hover:bg-red-50 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          </div>
        </div>

        {/* Textarea */}
        <textarea
          value={sourceCode}
          onChange={(e) => {
            setSourceCode(e.target.value);
            setAnalysisResult(null);
            setErrorMessage(null);
          }}
          placeholder="// Paste C or C++ firmware code here (e.g. ESP32, STM32, Arduino)...&#10;#include <stdio.h>&#10;&#10;void setup() {&#10;    // ...&#10;}"
          rows={16}
          className="w-full bg-[#0A0A0A] text-zinc-100 font-mono text-xs p-4 rounded-2xl border border-zinc-800 focus:outline-none focus:ring-2 focus:ring-[#D8ECF8] leading-relaxed resize-y"
          spellCheck={false}
        />

        {errorMessage && (
          <div className="flex items-center gap-2.5 p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-medium">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Action Button */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-zinc-400">
            Executes dual AST scanning (Semgrep C/C++ + VULNEX Embedded AST Engine)
          </span>
          <button
            type="button"
            onClick={handleRunAnalysis}
            disabled={isAnalyzing || !sourceCode.trim()}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-[#0A0A0A] text-white text-xs font-extrabold uppercase tracking-wider hover:bg-zinc-800 disabled:opacity-50 transition-all cursor-pointer shadow-sm"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-[#D8ECF8]" />
                Analyzing Firmware Security...
              </>
            ) : (
              <>
                <Cpu className="w-4 h-4 text-[#D8ECF8]" />
                Execute Firmware Security Analysis
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Results Display */}
      {analysisResult && (
        <div className="space-y-6">
          {/* Executive Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white rounded-2xl p-5 border border-zinc-200/80 shadow-sm">
              <span className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider">
                Vulnerabilities
              </span>
              <div className="text-2xl font-black text-zinc-900 mt-1 tabular-nums">
                {analysisResult.summary.total}
              </div>
              <div className="text-[11px] text-zinc-500 mt-1">
                {analysisResult.summary.critical} critical · {analysisResult.summary.high} high
              </div>
            </div>

            <div className="bg-white rounded-2xl p-5 border border-zinc-200/80 shadow-sm">
              <span className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider">
                Lines of Code
              </span>
              <div className="text-2xl font-black text-zinc-900 mt-1 tabular-nums">
                {analysisResult.lines_of_code}
              </div>
              <div className="text-[11px] text-zinc-500 mt-1">Embedded C/C++ source</div>
            </div>

            <div className="bg-white rounded-2xl p-5 border border-zinc-200/80 shadow-sm">
              <span className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider">
                Target Architecture
              </span>
              <div className="text-xl font-black text-zinc-900 mt-1 uppercase">
                {analysisResult.target_platform}
              </div>
              <div className="text-[11px] text-zinc-500 mt-1">{analysisResult.rtos || 'Bare Metal'}</div>
            </div>

            <div className="bg-white rounded-2xl p-5 border border-zinc-200/80 shadow-sm">
              <span className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider">
                Scan Latency
              </span>
              <div className="text-2xl font-black text-zinc-900 mt-1 tabular-nums">
                {analysisResult.duration_ms}ms
              </div>
              <div className="text-[11px] text-emerald-600 font-semibold mt-1">AST Verified</div>
            </div>
          </div>

          {/* Risk Domain Breakdown */}
          {analysisResult.risk_breakdown && (
            <div className="bg-white rounded-[24px] p-6 border border-zinc-200/80 shadow-sm">
              <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-4">
                Firmware Risk Breakdown by Domain
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                {Object.entries(analysisResult.risk_breakdown).map(([domain, count]) => (
                  <div
                    key={domain}
                    className={`p-3.5 rounded-xl border text-center ${
                      count > 0 ? 'bg-red-50/60 border-red-200' : 'bg-zinc-50 border-zinc-200/60'
                    }`}
                  >
                    <div className="text-[11px] font-bold uppercase text-zinc-600">{domain}</div>
                    <div
                      className={`text-xl font-extrabold mt-1 tabular-nums ${
                        count > 0 ? 'text-red-700' : 'text-zinc-400'
                      }`}
                    >
                      {count}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detailed Findings List */}
          <div className="bg-white rounded-[28px] p-6 border border-zinc-200/80 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-extrabold text-zinc-900">
                Identified Security Flaws ({analysisResult.findings.length})
              </h3>
              {analysisResult.findings.length > 0 && (
                <button
                  type="button"
                  onClick={() => onNavigateTab('vulnerabilities')}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-zinc-900 hover:text-zinc-600"
                >
                  View in Main Vulnerabilities Tab
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {analysisResult.findings.length === 0 ? (
              <div className="text-center py-12 text-zinc-400">
                <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500 mb-2" />
                <p className="text-sm font-semibold text-zinc-700">No firmware vulnerabilities detected</p>
                <p className="text-xs text-zinc-500 mt-1">Submitted embedded code conforms to verified secure memory and communication policies.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {analysisResult.findings.map((f, idx) => (
                  <div
                    key={f.id || idx}
                    className="p-5 rounded-2xl border border-zinc-200 bg-zinc-50/50 hover:border-zinc-300 transition-all space-y-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full uppercase tracking-wider ${
                            f.severity === 'CRITICAL'
                              ? 'bg-red-100 text-red-800'
                              : f.severity === 'HIGH'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-blue-100 text-blue-800'
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="text-xs font-mono font-bold text-zinc-600">
                          {f.cwe}
                        </span>
                        <span className="text-xs font-mono font-semibold text-zinc-500">
                          CVSS: {f.cvss}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-zinc-400">
                        {f.filePath}:{f.lineStart}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-sm font-bold text-zinc-900">{f.title}</h4>
                      <p className="text-xs text-zinc-600 mt-1 leading-relaxed">{f.summary}</p>
                    </div>

                    {/* Code Snippet */}
                    {f.vulnerableSnippet && (
                      <div className="bg-[#0A0A0A] rounded-xl p-3 font-mono text-xs text-red-300 overflow-x-auto">
                        <div className="text-[10px] text-zinc-500 mb-1">
                          Vulnerable Code Snippet (Line {f.lineStart}):
                        </div>
                        <code>{f.vulnerableSnippet}</code>
                      </div>
                    )}

                    {/* Threat Impact & Recommendation */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
                      <div className="bg-red-50/60 border border-red-100 rounded-xl p-3 text-red-900">
                        <span className="font-bold block mb-1">Potential Threat Impact:</span>
                        {f.rootCauseAnalysis}
                      </div>
                      <div className="bg-emerald-50/60 border border-emerald-100 rounded-xl p-3 text-emerald-900">
                        <span className="font-bold block mb-1">Recommended Hardening:</span>
                        {f.astTransformationStrategy}
                      </div>
                    </div>

                    {/* Action Bar */}
                    <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-200/60">
                      <button
                        type="button"
                        onClick={() => handleTriggerRefactor(f)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0A0A0A] text-white text-xs font-bold hover:bg-zinc-800 cursor-pointer"
                      >
                        <Sparkles className="w-3.5 h-3.5 text-[#D8ECF8]" />
                        Refactor with AI Engine
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Code Refactoring Modal / Drawer */}
      {refactorFinding && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white rounded-[28px] max-w-3xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-100">
              <div>
                <h3 className="text-base font-extrabold text-zinc-900">
                  Firmware Vulnerability Refactoring Engine
                </h3>
                <p className="text-xs text-zinc-500 mt-0.5">
                  Target: {refactorFinding.title} ({refactorFinding.cwe})
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setRefactorFinding(null);
                  setRefactorResult(null);
                }}
                className="w-7 h-7 rounded-full bg-zinc-100 hover:bg-zinc-200 flex items-center justify-center text-xs font-bold cursor-pointer"
              >
                ✕
              </button>
            </div>

            {isRefactoring ? (
              <div className="py-16 text-center space-y-3">
                <Loader2 className="w-8 h-8 animate-spin mx-auto text-[#0A0A0A]" />
                <p className="text-xs font-bold text-zinc-700">Synthesizing memory-safe hardened component...</p>
              </div>
            ) : refactorResult ? (
              <div className="space-y-4">
                {refactorResult.error ? (
                  <div className="p-4 rounded-xl bg-red-50 text-red-800 text-xs">
                    {refactorResult.error}
                  </div>
                ) : (
                  <>
                    <div className="space-y-1.5">
                      <span className="text-xs font-bold text-zinc-700">Refactored Safe Source Code:</span>
                      <pre className="bg-[#0A0A0A] text-emerald-300 font-mono text-xs p-4 rounded-xl overflow-x-auto leading-relaxed">
                        {refactorResult.secure_code}
                      </pre>
                    </div>

                    {refactorResult.diff && (
                      <div className="space-y-1.5">
                        <span className="text-xs font-bold text-zinc-700">Unified AST Diff:</span>
                        <pre className="bg-zinc-900 text-zinc-200 font-mono text-xs p-3.5 rounded-xl overflow-x-auto">
                          {refactorResult.diff}
                        </pre>
                      </div>
                    )}

                    {refactorResult.security_benefits && (
                      <div className="bg-emerald-50 rounded-xl p-3 text-xs text-emerald-900 space-y-1">
                        <span className="font-bold block">Security Guarantees Applied:</span>
                        <ul className="list-disc list-inside space-y-0.5">
                          {refactorResult.security_benefits.map((b: string, i: number) => (
                            <li key={i}>{b}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}
              </div>
            ) : null}

            <div className="flex justify-end pt-3 border-t border-zinc-100">
              <button
                type="button"
                onClick={() => {
                  setRefactorFinding(null);
                  setRefactorResult(null);
                }}
                className="px-4 py-2 rounded-xl bg-zinc-100 text-zinc-800 text-xs font-bold hover:bg-zinc-200 cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
