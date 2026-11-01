import React, { useState, useRef, ChangeEvent } from 'react';
import {
  ScanSearch,
  AlertCircle,
  Check,
  ArrowUpRight,
  Code2,
  FileCode,
  Upload,
  Archive,
  Trash2,
  Loader2,
  FileText,
} from 'lucide-react';
import { ScanFormInput, NavigationTab } from '../types/security';

interface NewScanViewProps {
  onLaunchScan: (
    input: ScanFormInput,
    customSourceCode?: string,
    customFilename?: string,
    zipFile?: File,
    language?: string,
    targetPlatform?: string,
    compiler?: string
  ) => Promise<void> | void;
  onNavigateTab: (tab: NavigationTab) => void;
  isScanning?: boolean;
}

const SUPPORTED_LANGUAGES = [
  { id: 'python', label: 'Python (.py)', ext: '.py' },
  { id: 'c', label: 'C Source / Header (.c, .h)', ext: '.c' },
  { id: 'cpp', label: 'C++ Source / Header (.cpp, .cc, .hpp)', ext: '.cpp' },
  { id: 'javascript', label: 'JavaScript (.js)', ext: '.js' },
  { id: 'typescript', label: 'TypeScript (.ts)', ext: '.ts' },
  { id: 'go', label: 'Go (.go)', ext: '.go' },
  { id: 'shell', label: 'Shell (.sh)', ext: '.sh' },
];

const MAX_CODE_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_ZIP_BYTES = 20 * 1024 * 1024; // 20 MB

export const NewScanView: React.FC<NewScanViewProps> = ({
  onLaunchScan,
  onNavigateTab,
  isScanning = false,
}) => {
  // Starts COMPLETELY BLANK: No preloaded vulnerable code or fixtures
  const [sourceCode, setSourceCode] = useState<string>('');
  const [language, setLanguage] = useState<string>('python');
  const [targetPlatform, setTargetPlatform] = useState<string>('generic');
  const [compiler, setCompiler] = useState<string>('gcc');
  const [filename, setFilename] = useState<string>('example.py');
  const [selectedZip, setSelectedZip] = useState<File | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [enableAutoPatch, setEnableAutoPatch] = useState<boolean>(true);
  const [enableSandboxReplay, setEnableSandboxReplay] = useState<boolean>(true);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);

  // Synchronize scroll between line numbers column and textarea
  const handleScroll = () => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  const lines = sourceCode.split('\n');
  const lineCount = Math.max(1, lines.length);

  // Handle language switch
  const handleLanguageChange = (e: ChangeEvent<HTMLSelectElement>) => {
    const newLang = e.target.value;
    setLanguage(newLang);
    const langObj = SUPPORTED_LANGUAGES.find((l) => l.id === newLang);
    if (langObj && filename.includes('.')) {
      const base = filename.substring(0, filename.lastIndexOf('.'));
      setFilename(`${base}${langObj.ext}`);
    }
    setValidationError(null);
  };

  // Upload single source file (.py, .js, .ts, etc.)
  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > MAX_CODE_BYTES) {
      setValidationError(`Selected file exceeds maximum allowed limit of 2 MB (${(file.size / 1024 / 1024).toFixed(1)} MB).`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setSourceCode(content || '');
      setFilename(file.name);
      setSelectedZip(null);

      // Auto-detect language extension
      const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
      if (ext === '.c' || ext === '.h') {
        setLanguage('c');
      } else if (ext === '.cpp' || ext === '.cc' || ext === '.cxx' || ext === '.hpp') {
        setLanguage('cpp');
      } else {
        const matched = SUPPORTED_LANGUAGES.find((l) => l.ext === ext);
        if (matched) {
          setLanguage(matched.id);
        }
      }
      setValidationError(null);
    };
    reader.onerror = () => {
      setValidationError('Failed to read file contents. Please verify file encoding.');
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  // Upload project ZIP archive
  const handleZipUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.zip')) {
      setValidationError('Selected archive must be a valid .zip file.');
      return;
    }

    if (file.size > MAX_ZIP_BYTES) {
      setValidationError(`Selected ZIP archive exceeds maximum 20 MB limit (${(file.size / 1024 / 1024).toFixed(1)} MB).`);
      return;
    }

    setSelectedZip(file);
    setFilename(file.name);
    setValidationError(null);
    e.target.value = '';
  };

  // Clear code button
  const handleClear = () => {
    setSourceCode('');
    setSelectedZip(null);
    setFilename(language === 'python' ? 'example.py' : `example.${SUPPORTED_LANGUAGES.find(l => l.id === language)?.ext || 'py'}`);
    setValidationError(null);
  };

  // Analyze Code submit handler
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (selectedZip) {
      const payload: ScanFormInput = {
        repository: selectedZip.name,
        branch: 'main',
        engineProfile: 'Full AST + Sandbox Replay',
        enableAutoPatch,
        enableSandboxReplay,
      };
      onLaunchScan(payload, undefined, selectedZip.name, selectedZip, language, targetPlatform, compiler);
      return;
    }

    if (!sourceCode || sourceCode.trim().length === 0) {
      setValidationError('Please enter or paste source code before analyzing, or click a sample button above.');
      return;
    }

    const payload: ScanFormInput = {
      repository: filename || 'custom_code.py',
      branch: 'main',
      engineProfile: 'Full AST + Sandbox Replay',
      enableAutoPatch,
      enableSandboxReplay,
    };

    onLaunchScan(payload, sourceCode, filename, undefined, language, targetPlatform, compiler);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
      {/* Left Column: Professional Code Input Studio (8 cols) */}
      <section className="lg:col-span-8 bg-white text-[#0A0A0A] rounded-[30px] p-7 flex flex-col justify-between shadow-sm border border-black/5">
        <div>
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[#0A0A0A]/10">
            <div>
              <span className="px-3 py-1 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-xs font-extrabold uppercase tracking-wide">
                Custom Source Analysis
              </span>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight mt-1 text-[#0A0A0A]">
                Submit Source Code for Security Scan
              </h1>
            </div>

            {/* Language & Architecture Selectors */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <label htmlFor="language-select" className="text-xs font-bold text-[#52525B]">
                  Language:
                </label>
                <select
                  id="language-select"
                  value={language}
                  onChange={handleLanguageChange}
                  className="px-3.5 py-1.5 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold border-none focus:outline-none focus:ring-2 focus:ring-[#0A0A0A] cursor-pointer"
                >
                  {SUPPORTED_LANGUAGES.map((lang) => (
                    <option key={lang.id} value={lang.id}>
                      {lang.label}
                    </option>
                  ))}
                </select>
              </div>

              {(language === 'c' || language === 'cpp') && (
                <>
                  <div className="flex items-center gap-2">
                    <label htmlFor="platform-select" className="text-xs font-bold text-[#52525B]">
                      Platform:
                    </label>
                    <select
                      id="platform-select"
                      value={targetPlatform}
                      onChange={(e) => setTargetPlatform(e.target.value)}
                      className="px-3 py-1.5 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold border-none focus:outline-none focus:ring-2 focus:ring-[#0A0A0A] cursor-pointer"
                    >
                      <option value="generic">Host Generic</option>
                      <option value="esp32">ESP32 / ESP-IDF</option>
                      <option value="stm32">STM32 / Cortex-M</option>
                      <option value="freertos">FreeRTOS</option>
                      <option value="zephyr">Zephyr RTOS</option>
                      <option value="arduino">Arduino</option>
                      <option value="rp2040">RP2040 Pico</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <label htmlFor="compiler-select" className="text-xs font-bold text-[#52525B]">
                      Compiler:
                    </label>
                    <select
                      id="compiler-select"
                      value={compiler}
                      onChange={(e) => setCompiler(e.target.value)}
                      className="px-3 py-1.5 rounded-full bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold border-none focus:outline-none focus:ring-2 focus:ring-[#0A0A0A] cursor-pointer"
                    >
                      <option value="gcc">GCC</option>
                      <option value="g++">G++</option>
                      <option value="clang">Clang</option>
                      <option value="clang++">Clang++</option>
                      <option value="arm-none-eabi-gcc">ARM GCC</option>
                    </select>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Action Toolbar: Upload File, Upload ZIP, Clear */}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".py,.c,.cpp,.cc,.cxx,.h,.hpp,.js,.ts,.go,.sh,.txt"
                onChange={handleFileUpload}
                className="hidden"
                id="source-file-upload"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="px-3.5 py-1.5 rounded-full bg-[#F4F8FB] hover:bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold border border-[#0A0A0A]/10 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Upload Source File</span>
              </button>

              <input
                ref={zipInputRef}
                type="file"
                accept=".zip"
                onChange={handleZipUpload}
                className="hidden"
                id="zip-archive-upload"
              />
              <button
                type="button"
                onClick={() => zipInputRef.current?.click()}
                className="px-3.5 py-1.5 rounded-full bg-[#F4F8FB] hover:bg-[#E5F2FA] text-[#0A0A0A] text-xs font-bold border border-[#0A0A0A]/10 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Archive className="w-3.5 h-3.5" />
                <span>Upload Project ZIP</span>
              </button>

              {(sourceCode.length > 0 || selectedZip) && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="px-3.5 py-1.5 rounded-full bg-[#FEE2E2] hover:bg-[#FECDD3] text-[#E11D48] text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear Code</span>
                </button>
              )}
            </div>

            {/* Live Stats */}
            <div className="flex items-center gap-3 text-xs font-mono text-[#52525B]">
              <span>LOC: {sourceCode ? lineCount : 0}</span>
              <span>Chars: {sourceCode.length}</span>
            </div>
          </div>

          {/* ZIP Archive Banner if selected */}
          {selectedZip && (
            <div className="mt-4 p-4 rounded-[20px] bg-[#E5F2FA] border border-[#0A0A0A]/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Archive className="w-6 h-6 text-[#0A0A0A]" />
                <div>
                  <div className="text-xs font-bold text-[#0A0A0A]">
                    {selectedZip.name}
                  </div>
                  <div className="text-[11px] text-[#52525B]">
                    Project ZIP Archive · {(selectedZip.size / 1024).toFixed(1)} KB · Ready to scan
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedZip(null)}
                className="text-xs font-bold text-[#E11D48] hover:underline cursor-pointer"
              >
                Remove
              </button>
            </div>
          )}

          {/* Filename Input */}
          <div className="mt-4 flex items-center gap-3">
            <label htmlFor="filename-field" className="text-xs font-bold text-[#52525B]">
              Target Filename:
            </label>
            <input
              id="filename-field"
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="example.py"
              className="px-3.5 py-1.5 rounded-full bg-[#F4F8FB] text-xs font-mono text-[#0A0A0A] border border-[#0A0A0A]/10 focus:outline-none focus:ring-2 focus:ring-[#0A0A0A]"
            />
          </div>

          {/* Quick Sample Selector Chips for Instant Testing */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold text-[#52525B]">Sample Test Snippets:</span>
            <button
              type="button"
              onClick={() => {
                setLanguage('c');
                setTargetPlatform('generic');
                setCompiler('gcc');
                setFilename('vulnerable_network.c');
                setSourceCode(
`#include <stdio.h>
#include <string.h>

void process_request() {
    char buffer[32];
    printf("Enter command: ");
    gets(buffer);
    printf(buffer);
}

int main() {
    process_request();
    return 0;
}`
                );
                setSelectedZip(null);
                setValidationError(null);
              }}
              className="px-3 py-1 rounded-full bg-[#E5F2FA] hover:bg-[#D8ECF8] text-[#0A0A0A] text-[11px] font-bold transition-colors cursor-pointer border border-[#0A0A0A]/10"
            >
              Load Vulnerable C Sample
            </button>
            <button
              type="button"
              onClick={() => {
                setLanguage('python');
                setFilename('vulnerable_api.py');
                setSourceCode(
`import sqlite3
import os

def query_user(user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    os.system(f"echo User lookup requested for {user_id}")
    return cursor.fetchall()
`
                );
                setSelectedZip(null);
                setValidationError(null);
              }}
              className="px-3 py-1 rounded-full bg-[#E5F2FA] hover:bg-[#D8ECF8] text-[#0A0A0A] text-[11px] font-bold transition-colors cursor-pointer border border-[#0A0A0A]/10"
            >
              Load Vulnerable Python Sample
            </button>
          </div>

          {/* Large Code Editor Interface with Line Numbers */}
          <form onSubmit={handleSubmit} className="mt-3">
            <div className="rounded-[22px] bg-[#0A0A0A] overflow-hidden border border-[#0A0A0A] shadow-inner relative flex">
              {/* Line Numbers Column */}
              <div
                ref={lineNumbersRef}
                aria-hidden="true"
                className="select-none py-4 pl-3 pr-2 text-right font-mono text-xs text-[#52525B] bg-[#121214] border-r border-white/5 overflow-hidden w-12 shrink-0 leading-relaxed"
                style={{ height: '360px' }}
              >
                {Array.from({ length: lineCount }, (_, i) => (
                  <div key={i + 1}>{i + 1}</div>
                ))}
              </div>

              {/* Code Input Area */}
              <textarea
                ref={textareaRef}
                value={sourceCode}
                onChange={(e) => {
                  setSourceCode(e.target.value);
                  setValidationError(null);
                }}
                onScroll={handleScroll}
                placeholder="Paste your source code here..."
                rows={16}
                spellCheck={false}
                className="w-full p-4 bg-[#0A0A0A] text-[#D8ECF8] font-mono text-xs leading-relaxed focus:outline-none resize-none"
                style={{ height: '360px' }}
              />
            </div>

            {/* Validation Error Banner */}
            {validationError && (
              <div
                role="alert"
                className="mt-4 p-4 rounded-[20px] bg-[#E11D48] text-white text-xs font-bold flex items-center gap-2.5"
              >
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{validationError}</span>
              </div>
            )}

            {/* Scan Controls & Options */}
            <div className="mt-5 pt-4 border-t border-[#0A0A0A]/10 flex flex-wrap items-center justify-between gap-4">
              <div className="flex flex-wrap items-center gap-4 text-xs font-semibold text-[#52525B]">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableAutoPatch}
                    onChange={(e) => setEnableAutoPatch(e.target.checked)}
                    className="rounded accent-[#0A0A0A]"
                  />
                  <span>Synthesize AST Patches</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableSandboxReplay}
                    onChange={(e) => setEnableSandboxReplay(e.target.checked)}
                    className="rounded accent-[#0A0A0A]"
                  />
                  <span>Sandbox Exploit Replay</span>
                </label>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-7 py-3.5 rounded-full bg-[#0A0A0A] text-white text-xs font-extrabold hover:bg-[#27272A] transition-colors flex items-center gap-2.5 cursor-pointer disabled:opacity-50 shadow-sm"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin text-[#D8ECF8]" />
                      <span>Running Security Pipeline...</span>
                    </>
                  ) : (
                    <>
                      <ScanSearch className="w-4 h-4" />
                      <span>Analyze Code</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      </section>

      {/* Right Column: Engine Architecture & Guarantees (4 cols) */}
      <aside className="lg:col-span-4 bg-[#0A0A0A] text-white rounded-[30px] p-7 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-[#D8ECF8] uppercase tracking-wider">
              Real Security Pipeline
            </span>
            <span className="w-2.5 h-2.5 rounded-full bg-[#059669] animate-pulse" />
          </div>

          <h2 className="text-2xl font-bold tracking-tight mt-4">
            Zero Execution On Host
          </h2>
          <p className="text-xs text-[#A1A1AA] mt-2 leading-relaxed">
            All submitted code is evaluated statically using Abstract Syntax Tree traversal, Bandit rule AST visitors, and Semgrep pattern engines. No submitted code is executed inside the API server.
          </p>

          <div className="mt-6 space-y-3">
            <div className="p-4 rounded-[22px] bg-white/5 border border-white/10">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Check className="w-4 h-4 text-[#D8ECF8]" />
                <span>Deterministic AST Analysis</span>
              </div>
              <p className="text-[11px] text-[#A1A1AA] mt-1">
                Pinpoints exact AST nodes: SQL queries, shell commands, deserialization sinks.
              </p>
            </div>

            <div className="p-4 rounded-[22px] bg-white/5 border border-white/10">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Check className="w-4 h-4 text-[#D8ECF8]" />
                <span>Genuine Vulnerability Output</span>
              </div>
              <p className="text-[11px] text-[#A1A1AA] mt-1">
                Returns actual findings from Bandit and Semgrep. If code is clean, 0 findings are reported.
              </p>
            </div>

            <div className="p-4 rounded-[22px] bg-white/5 border border-white/10">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Check className="w-4 h-4 text-[#D8ECF8]" />
                <span>Multi-Stage Check Validation</span>
              </div>
              <p className="text-[11px] text-[#A1A1AA] mt-1">
                Patches are re-scanned statically. Checks show NOT RUN until genuinely verified.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-white/10 flex items-center justify-between text-xs text-[#A1A1AA]">
          <span>REST Pipeline: /api/v1/scans</span>
          <span className="font-mono text-[#D8ECF8]">FastAPI Engine</span>
        </div>
      </aside>
    </div>
  );
};
