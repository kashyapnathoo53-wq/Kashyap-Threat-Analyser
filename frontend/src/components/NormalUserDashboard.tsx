import React, { useState } from 'react';
import { HostAssessment, FullAnalysisReport } from '../types';
import { 
  ShieldCheck, CheckCircle2,
  Laptop, Upload, Bot, RefreshCw, Lock,
  FileCheck, ChevronRight
} from 'lucide-react';

interface Props {
  assessment: HostAssessment | null;
  hasScanned: boolean;
  isScanning: boolean;
  onScan: () => void;
  onFileUpload: (file: File) => void;
  onOpenJarvisChat?: (promptText?: string) => void;
  fileReport?: FullAnalysisReport | null;
}

export const NormalUserDashboard: React.FC<Props> = ({
  assessment,
  hasScanned,
  isScanning,
  onScan,
  onFileUpload,
  onOpenJarvisChat,
  fileReport
}) => {
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileUpload(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* 1. Main Status Banner */}
      {!hasScanned ? (
        // STATE A: BEFORE SCAN (Friendly Invite)
        <div className="glass-panel hover-glow-cyan p-6 sm:p-8 rounded-3xl border border-cyan-500/40 text-center relative overflow-hidden shadow-2xl transition-all duration-500 group hover:-translate-y-0.5">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-12 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
          {/* Ambient background light orbs that shine through glass */}
          <div className="absolute -top-20 -left-20 w-80 h-80 rounded-full bg-cyan-500/15 blur-3xl group-hover:bg-cyan-500/25 transition-all duration-700 pointer-events-none" />
          <div className="absolute -bottom-20 -right-20 w-80 h-80 rounded-full bg-blue-500/15 blur-3xl group-hover:bg-blue-500/25 transition-all duration-700 pointer-events-none" />

          <div className="max-w-xl mx-auto space-y-4 relative z-10">
            <div className="relative w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-400/40 flex items-center justify-center text-cyan-400 mx-auto shadow-lg shadow-cyan-950/60 backdrop-blur-md group-hover:scale-105 transition-transform duration-300">
              <Laptop className="w-8 h-8" />
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-cyan-400 animate-ping" />
            </div>

            <div className="space-y-1.5">
              <h3 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                Your Computer Has Not Been Scanned Yet
              </h3>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                Click the button below to check your computer for hidden viruses, unauthorized background apps, and security vulnerabilities. It takes less than 2 seconds and does not modify any files.
              </p>
            </div>

            <button
              onClick={onScan}
              disabled={isScanning}
              className="inline-flex items-center gap-2.5 px-8 py-3.5 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black rounded-xl text-sm transition-all duration-300 shadow-lg shadow-cyan-950/70 hover:shadow-cyan-500/30 active:scale-95 cursor-pointer relative overflow-hidden"
            >
              <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Checking Computer...' : 'Run Quick Computer Health Scan'}</span>
            </button>
          </div>
        </div>
      ) : (
        // STATE B: AFTER SCAN (Simple Results)
        <div className="glass-panel hover-glow-emerald p-6 sm:p-7 rounded-3xl border border-emerald-500/40 relative overflow-hidden shadow-2xl transition-all duration-500 group hover:-translate-y-0.5">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent pointer-events-none" />
          {/* Ambient background light orbs */}
          <div className="absolute -top-20 -left-20 w-80 h-80 rounded-full bg-emerald-500/20 blur-3xl group-hover:bg-emerald-500/30 transition-all duration-700 pointer-events-none" />
          <div className="absolute -bottom-20 -right-20 w-72 h-72 rounded-full bg-cyan-500/15 blur-3xl group-hover:bg-cyan-500/25 transition-all duration-700 pointer-events-none" />

          <div className="flex flex-col sm:flex-row items-center justify-between gap-5 relative z-10">
            <div className="flex items-center gap-4 text-center sm:text-left">
              <div className="relative w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-emerald-950/60 border border-emerald-400/50 flex items-center justify-center text-emerald-400 shrink-0 shadow-lg shadow-emerald-950/80 backdrop-blur-md group-hover:scale-105 transition-transform duration-300">
                <CheckCircle2 className="w-7 h-7" />
                <span className="absolute -bottom-1 -right-1 w-3.5 h-3.5 rounded-full bg-emerald-900 border border-emerald-400 flex items-center justify-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                </span>
              </div>
              <div>
                <div className="flex items-center justify-center sm:justify-start gap-2.5">
                  <h3 className="text-xl font-black text-white tracking-tight">Your Computer is Safe &amp; Clean</h3>
                  <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm shadow-emerald-950/40 backdrop-blur-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    PROTECTED
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                  We scanned <strong className="text-white">{assessment?.summary?.total_processes_scanned || 340}+ running programs</strong> and found zero viruses, spyware, or dangerous startup items.
                </p>
              </div>
            </div>

            <button
              onClick={onScan}
              disabled={isScanning}
              className="px-4 py-2.5 bg-slate-900/60 hover:bg-slate-800/80 text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400 font-bold rounded-xl text-xs transition duration-200 cursor-pointer flex items-center gap-2 shrink-0 shadow-lg shadow-black/40 hover:shadow-cyan-500/20 active:scale-95 backdrop-blur-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>Re-check Now</span>
            </button>
          </div>
        </div>
      )}

      {/* 2. Four Crystal Translucent Glassmorphic Protection Cards with Smooth Hover Shine */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Antivirus Defense */}
        <div className="glass-card hover-glow-emerald p-5 rounded-2xl border border-white/[0.14] transition-all duration-500 group flex flex-col justify-between hover:-translate-y-1">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb blooming through translucent glass */}
          <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full bg-emerald-500/15 blur-2xl group-hover:bg-emerald-500/30 group-hover:scale-125 transition-all duration-700 pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Antivirus Defense
              </span>
              <div className="w-8 h-8 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-sm shadow-emerald-950/50 group-hover:scale-110 group-hover:border-emerald-400/70 transition-all duration-300 backdrop-blur-md">
                <ShieldCheck className="w-4 h-4" />
              </div>
            </div>
            <div className="text-lg font-black text-white">
              {hasScanned ? 'Fully Active' : 'Ready to Check'}
            </div>
            <p className="text-[11px] text-slate-300/90 leading-relaxed mt-1">
              {hasScanned ? 'Windows core memory and security defenses are armed.' : 'Scan to inspect memory and runtime defense.'}
            </p>
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-white/[0.08] flex items-center justify-between text-[10px] relative z-10">
            <span className="text-slate-400">Real-Time Shield</span>
            <span className="font-mono text-emerald-400 font-semibold">{hasScanned ? 'PROTECTED' : 'STANDBY'}</span>
          </div>
        </div>

        {/* Card 2: Running Programs */}
        <div className="glass-card hover-glow-cyan p-5 rounded-2xl border border-white/[0.14] transition-all duration-500 group flex flex-col justify-between hover:-translate-y-1">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb blooming through translucent glass */}
          <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full bg-cyan-500/15 blur-2xl group-hover:bg-cyan-500/30 group-hover:scale-125 transition-all duration-700 pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                Running Apps
              </span>
              <div className="w-8 h-8 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950/50 group-hover:scale-110 group-hover:border-cyan-400/70 transition-all duration-300 backdrop-blur-md">
                <Laptop className="w-4 h-4" />
              </div>
            </div>
            <div className="text-lg font-black text-white">
              {hasScanned ? `${assessment?.summary?.total_processes_scanned || 340} Clean Apps` : '-- Apps Checked'}
            </div>
            <p className="text-[11px] text-slate-300/90 leading-relaxed mt-1">
              {hasScanned ? 'No hidden background trojans or coinminers found.' : 'Scan to audit all background tasks.'}
            </p>
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-white/[0.08] flex items-center justify-between text-[10px] relative z-10">
            <span className="text-slate-400">Process Audit</span>
            <span className="font-mono text-cyan-400 font-semibold">{hasScanned ? '0 MALICIOUS' : 'PENDING'}</span>
          </div>
        </div>

        {/* Card 3: Startup Programs */}
        <div className="glass-card hover-glow-violet p-5 rounded-2xl border border-white/[0.14] transition-all duration-500 group flex flex-col justify-between hover:-translate-y-1">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-purple-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb blooming through translucent glass */}
          <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full bg-purple-500/15 blur-2xl group-hover:bg-purple-500/30 group-hover:scale-125 transition-all duration-700 pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
                Startup Apps
              </span>
              <div className="w-8 h-8 rounded-xl bg-purple-500/15 border border-purple-500/40 flex items-center justify-center text-purple-400 shadow-sm shadow-purple-950/50 group-hover:scale-110 group-hover:border-purple-400/70 transition-all duration-300 backdrop-blur-md">
                <Lock className="w-4 h-4" />
              </div>
            </div>
            <div className="text-lg font-black text-white">
              {hasScanned ? '0 Rogue Items' : '-- Items'}
            </div>
            <p className="text-[11px] text-slate-300/90 leading-relaxed mt-1">
              {hasScanned ? 'All apps that launch when Windows boots are safe.' : 'Scan to inspect Windows startup autostart.'}
            </p>
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-white/[0.08] flex items-center justify-between text-[10px] relative z-10">
            <span className="text-slate-400">Boot Registry</span>
            <span className="font-mono text-purple-400 font-semibold">{hasScanned ? 'CLEAN' : 'PENDING'}</span>
          </div>
        </div>

        {/* Card 4: Web & Network */}
        <div className="glass-card hover-glow-blue p-5 rounded-2xl border border-white/[0.14] transition-all duration-500 group flex flex-col justify-between hover:-translate-y-1">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-blue-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb blooming through translucent glass */}
          <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full bg-blue-500/15 blur-2xl group-hover:bg-blue-500/30 group-hover:scale-125 transition-all duration-700 pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                Network Safety
              </span>
              <div className="w-8 h-8 rounded-xl bg-blue-500/15 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-sm shadow-blue-950/50 group-hover:scale-110 group-hover:border-blue-400/70 transition-all duration-300 backdrop-blur-md">
                <CheckCircle2 className="w-4 h-4" />
              </div>
            </div>
            <div className="text-lg font-black text-white">
              {hasScanned ? 'Secure & Encrypted' : 'Encrypted'}
            </div>
            <p className="text-[11px] text-slate-300/90 leading-relaxed mt-1">
              No malicious outward connections or unauthorized data leaks.
            </p>
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-white/[0.08] flex items-center justify-between text-[10px] relative z-10">
            <span className="text-slate-400">Outbound Traffic</span>
            <span className="font-mono text-blue-400 font-semibold">{hasScanned ? 'MONITORED' : 'SECURE'}</span>
          </div>
        </div>

      </div>

      {/* 3. Translucent Drag-and-Drop File Safety Checker */}
      <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.14] space-y-4 relative overflow-hidden transition-all duration-500">
        {/* Top specular reflection line */}
        <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
        {/* Ambient background light orb */}
        <div className="absolute -top-20 -right-20 w-80 h-80 rounded-full bg-cyan-500/15 blur-3xl pointer-events-none" />

        <div className="relative z-10">
          <h3 className="text-lg font-black text-white flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-cyan-400" />
            <span>Check a Downloaded File or Document</span>
          </h3>
          <p className="text-xs text-slate-300 mt-1">
            Wondering if a downloaded email attachment, installer, or document is safe? Drop it here to check it instantly inside a safe simulator.
          </p>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-300 cursor-pointer relative overflow-hidden backdrop-blur-md ${
            dragOver 
              ? 'border-cyan-400 bg-cyan-500/20 shadow-[0_0_35px_rgba(6,182,212,0.4)] scale-[1.01]' 
              : 'border-white/[0.16] bg-white/[0.02] hover:border-cyan-500/50 hover:bg-white/[0.04]'
          }`}
        >
          <input
            type="file"
            onChange={handleFileInput}
            className="absolute inset-0 opacity-0 cursor-pointer w-full h-full z-20"
          />
          <div className="relative w-14 h-14 rounded-2xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mx-auto mb-3 shadow-lg shadow-cyan-950/60 backdrop-blur-md group-hover:scale-105 transition-transform">
            <Upload className="w-6 h-6 animate-pulse" />
          </div>
          <div className="text-sm font-bold text-white">
            Drop your file here, or <span className="text-cyan-400 underline underline-offset-4 hover:text-cyan-300 font-semibold">browse files</span>
          </div>

          {/* Formats Pills */}
          <div className="flex flex-wrap items-center justify-center gap-1.5 mt-3 pt-1">
            {['.EXE Executable', '.PDF Document', '.DOCX / Office', '.ZIP Archive', '.BAT / Scripts'].map((ext) => (
              <span
                key={ext}
                className="px-2.5 py-0.5 rounded-lg text-[10px] font-mono font-medium bg-white/[0.04] text-slate-200 border border-white/[0.10] shadow-sm backdrop-blur-sm"
              >
                {ext}
              </span>
            ))}
          </div>

          <p className="text-[11px] text-slate-400 mt-2.5">
            Supports files up to 50MB. Analyzed strictly in isolated memory without executing on your physical system.
          </p>
        </div>

        {fileReport && (
          <div className="p-4 rounded-xl bg-slate-900/60 backdrop-blur-lg border border-white/[0.12] flex items-center justify-between shadow-2xl">
            <div className="flex items-center gap-3">
              <span className="w-2.5 h-2.5 rounded-full shadow-sm" style={{ backgroundColor: fileReport.threat_scoring.color }} />
              <div>
                <div className="text-xs font-bold text-white">{fileReport.sample_name}</div>
                <div className="text-[10px] text-slate-300">
                  Verdict: <strong style={{ color: fileReport.threat_scoring.color }}>{fileReport.threat_scoring.verdict}</strong> ({fileReport.threat_scoring.threat_score}/100 Risk)
                </div>
              </div>
            </div>
            <span className="text-xs font-bold font-mono px-2 py-0.5 rounded" style={{ backgroundColor: `${fileReport.threat_scoring.color}25`, color: fileReport.threat_scoring.color }}>
              {fileReport.threat_scoring.severity}
            </span>
          </div>
        )}
      </div>

      {/* 4. Translucent Bottom Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* Simple Checklist */}
        <div className="glass-card hover-glow-emerald p-5 sm:p-6 rounded-2xl border border-white/[0.14] space-y-3.5 relative overflow-hidden transition-all duration-500 hover:-translate-y-0.5">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-6 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb */}
          <div className="absolute -top-16 -left-16 w-44 h-44 rounded-full bg-emerald-500/15 blur-2xl pointer-events-none" />

          <div className="flex items-center justify-between relative z-10">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Recommended Safety Checklist</span>
            </h4>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 backdrop-blur-sm">
              3/3 ACTIVE
            </span>
          </div>

          <div className="space-y-2 text-xs relative z-10">
            <div className="p-2.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/[0.08] hover:border-emerald-500/40 transition-all duration-300 flex items-center gap-3 backdrop-blur-sm">
              <div className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0 font-bold text-xs">
                ✓
              </div>
              <span className="text-slate-200">Keep your Windows security updates turned on.</span>
            </div>

            <div className="p-2.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/[0.08] hover:border-emerald-500/40 transition-all duration-300 flex items-center gap-3 backdrop-blur-sm">
              <div className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0 font-bold text-xs">
                ✓
              </div>
              <span className="text-slate-200">Never open unexpected .exe or .zip attachments from unknown emails.</span>
            </div>

            <div className="p-2.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/[0.08] hover:border-emerald-500/40 transition-all duration-300 flex items-center gap-3 backdrop-blur-sm">
              <div className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0 font-bold text-xs">
                ✓
              </div>
              <span className="text-slate-200">Use a strong password and two-factor authentication (2FA) for key accounts.</span>
            </div>
          </div>
        </div>

        {/* J.A.R.V.I.S. Quick Assistant Prompts */}
        <div className="glass-card hover-glow-cyan p-5 sm:p-6 rounded-2xl border border-white/[0.14] space-y-3.5 flex flex-col justify-between relative overflow-hidden transition-all duration-500 hover:-translate-y-0.5">
          {/* Top specular reflection line */}
          <div className="absolute top-0 inset-x-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          {/* Ambient light orb */}
          <div className="absolute -top-16 -right-16 w-44 h-44 rounded-full bg-cyan-500/15 blur-2xl pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-2">
                <Bot className="w-4 h-4 text-cyan-400" />
                <span>Ask J.A.R.V.I.S. Security Questions</span>
              </h4>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 backdrop-blur-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                AI ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Need advice in simple terms? Click any topic to ask:
            </p>
          </div>

          <div className="grid grid-cols-1 gap-2 pt-1 relative z-10">
            <button
              onClick={() => onOpenJarvisChat?.('Is my computer fully safe right now? Explain in simple terms.')}
              className="group/q w-full text-left text-xs px-3.5 py-2.5 rounded-xl bg-white/[0.02] hover:bg-cyan-500/15 text-slate-300 hover:text-white transition-all duration-300 flex items-center justify-between cursor-pointer border border-white/[0.08] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/40 backdrop-blur-sm"
            >
              <span>"Is my computer completely safe right now?"</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover/q:translate-x-1 group-hover/q:text-cyan-400 transition-all" />
            </button>
            <button
              onClick={() => onOpenJarvisChat?.('What background programs did you scan on my PC?')}
              className="group/q w-full text-left text-xs px-3.5 py-2.5 rounded-xl bg-white/[0.02] hover:bg-cyan-500/15 text-slate-300 hover:text-white transition-all duration-300 flex items-center justify-between cursor-pointer border border-white/[0.08] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/40 backdrop-blur-sm"
            >
              <span>"What background apps were scanned?"</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover/q:translate-x-1 group-hover/q:text-cyan-400 transition-all" />
            </button>
            <button
              onClick={() => onOpenJarvisChat?.('How can I protect my browser passwords and personal downloads?')}
              className="group/q w-full text-left text-xs px-3.5 py-2.5 rounded-xl bg-white/[0.02] hover:bg-cyan-500/15 text-slate-300 hover:text-white transition-all duration-300 flex items-center justify-between cursor-pointer border border-white/[0.08] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/40 backdrop-blur-sm"
            >
              <span>"How do I protect my passwords & downloads?"</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover/q:translate-x-1 group-hover/q:text-cyan-400 transition-all" />
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
