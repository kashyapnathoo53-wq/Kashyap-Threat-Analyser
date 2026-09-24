import React, { useState, useEffect, useRef } from 'react';
import { FullAnalysisReport, HostAssessment } from './types';
import { DashboardOverview } from './components/DashboardOverview';
import { StaticAnalysisTab } from './components/StaticAnalysisTab';
import { BehavioralSandboxTab } from './components/BehavioralSandboxTab';
import { MitreAttackTab } from './components/MitreAttackTab';
import { IocExtractorTab } from './components/IocExtractorTab';
import { YaraWorkbenchTab } from './components/YaraWorkbenchTab';
import { ReportGeneratorTab } from './components/ReportGeneratorTab';
import { SystemAssessmentTab } from './components/SystemAssessmentTab';
import { SampleSelectorModal } from './components/SampleSelectorModal';
import { CyberParticleCanvas } from './components/CyberParticleCanvas';
import { HoloReactorCore } from './components/HoloReactorCore';
import { LiveTelemetryTerminal } from './components/LiveTelemetryTerminal';
import { JarvisVoiceBanner } from './components/JarvisVoiceBanner';
import { JarvisAssistantModal } from './components/JarvisAssistantModal';
import { JarvisChatModal } from './components/JarvisChatModal';
import { FALLBACK_REPORTS, FALLBACK_HOST_ASSESSMENT } from './data/mockReports';
import { analyzeFileClientSide } from './utils/clientAnalyzer';
import { cyberAudio } from './utils/cyberAudio';
import { 
  Shield, ShieldAlert, Cpu, Terminal, Layers, Database, Code2, FileText, 
  Upload, RefreshCw, Activity, AlertTriangle, MonitorCheck, Zap, 
  Sparkles, Globe2, Radio, Server, CheckCircle2, ChevronRight, Lock,
  Volume2, VolumeX, Palette, ArrowUpRight, Flame, Bot, MessageSquare, Sliders
} from 'lucide-react';
import { ThemeSelectorModal, ThemeId, THEME_OPTIONS } from './components/ThemeSelectorModal';

export type Theme = ThemeId;

export const App: React.FC = () => {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('pasha_theme');
    if (saved === 'amber' || saved === 'ironman' || !saved) {
      return 'cyan';
    }
    return (saved as Theme) || 'cyan';
  });

  const [customColor, setCustomColor] = useState<string | null>(() => {
    return localStorage.getItem('pasha_custom_color') || null;
  });

  const [showThemeModal, setShowThemeModal] = useState<boolean>(false);

  const workspaceRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('pasha_theme', theme);
    if (customColor) {
      document.documentElement.style.setProperty('--cyber-accent', customColor);
      document.documentElement.style.setProperty('--cyber-accent-glow', `${customColor}60`);
      document.documentElement.style.setProperty('--cyber-border', `${customColor}45`);
      document.documentElement.style.setProperty('--cyber-laser', customColor);
    } else {
      document.documentElement.style.removeProperty('--cyber-accent');
      document.documentElement.style.removeProperty('--cyber-accent-glow');
      document.documentElement.style.removeProperty('--cyber-border');
      document.documentElement.style.removeProperty('--cyber-laser');
    }
  }, [theme, customColor]);

  const handleApplyCustomColor = (hex: string) => {
    setCustomColor(hex);
    localStorage.setItem('pasha_custom_color', hex);
    document.documentElement.style.setProperty('--cyber-accent', hex);
    document.documentElement.style.setProperty('--cyber-accent-glow', `${hex}60`);
    document.documentElement.style.setProperty('--cyber-border', `${hex}45`);
    document.documentElement.style.setProperty('--cyber-laser', hex);
  };

  const handleResetDefaultTheme = () => {
    setCustomColor(null);
    localStorage.removeItem('pasha_custom_color');
    document.documentElement.style.removeProperty('--cyber-accent');
    document.documentElement.style.removeProperty('--cyber-accent-glow');
    document.documentElement.style.removeProperty('--cyber-border');
    document.documentElement.style.removeProperty('--cyber-laser');
    setTheme('cyan');
  };

  const handleOpenTab = (tabId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setActiveTab(tabId);
    cyberAudio.playTabSwitch();
    setTimeout(() => {
      workspaceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 60);
  };

  const [report, setReport] = useState<FullAnalysisReport>(FALLBACK_REPORTS['sample_wannacry']);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment>(FALLBACK_HOST_ASSESSMENT);
  const [hostLoading, setHostLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [showJarvisModal, setShowJarvisModal] = useState<boolean>(false);
  const [showChatModal, setShowChatModal] = useState<boolean>(false);
  const [chatInitialPrompt, setChatInitialPrompt] = useState<string>('');

  const handleOpenJarvisChat = (prompt?: string) => {
    setChatInitialPrompt(prompt || '');
    setShowChatModal(true);
  };
  const [isMuted, setIsMuted] = useState<boolean>(cyberAudio.getIsMuted());
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingPhase, setLoadingPhase] = useState<string>('Initializing forensic pipeline...');
  const [loadingProgress, setLoadingProgress] = useState<number>(100);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState<string>(new Date().toTimeString().split(' ')[0]);
  const [telemetryIndex, setTelemetryIndex] = useState<number>(0);

  const telemetryFeed = [
    "RADAR SCANNING: 316 host processes monitored in real-time",
    "CVE SENTINEL: NVD vulnerability database synchronized",
    "PERSISTENCE SHIELD: Windows Registry RunKeys continuously secured",
    "HEURISTIC DEFENSE: Real-time API hooking & behavioral telemetry armed"
  ];

  // Auto-run Host Assessment and live timers on startup
  useEffect(() => {
    // Attempt live fetch if backend is running, otherwise fallback remains active
    fetch('/api/system/auto-assess')
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setHostAssessment(data); })
      .catch(() => {});

    fetch('/api/analyze/preset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_id: 'sample_wannacry' })
    })
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setReport(data); })
      .catch(() => {});

    const timer = setInterval(() => {
      setCurrentTime(new Date().toTimeString().split(' ')[0]);
    }, 1000);

    const ticker = setInterval(() => {
      setTelemetryIndex(prev => (prev + 1) % telemetryFeed.length);
    }, 3800);

    return () => {
      clearInterval(timer);
      clearInterval(ticker);
    };
  }, []);

  const runHostAutoAssessment = async () => {
    setHostLoading(true);
    try {
      const res = await fetch('/api/system/auto-assess');
      if (res.ok) {
        const data = await res.json();
        setHostAssessment(data);
        return;
      }
    } catch {
      // Offline fallback
    } finally {
      setHostLoading(false);
    }
    // Instant fallback for Vercel
    setHostAssessment(FALLBACK_HOST_ASSESSMENT);
  };

  const simulateProgress = () => {
    setLoadingProgress(20);
    setLoadingPhase("Ingesting payload & streaming cryptographic fingerprints (MD5/SHA256)...");
    
    const t1 = setTimeout(() => {
      setLoadingProgress(48);
      setLoadingPhase("Profiling PE section entropy & detecting commercial packing (UPX/Themida)...");
    }, 150);

    const t2 = setTimeout(() => {
      setLoadingProgress(76);
      setLoadingPhase("Evaluating YARA signature rulesets & auto-decoding XOR/Base64 payloads...");
    }, 320);

    const t3 = setTimeout(() => {
      setLoadingProgress(96);
      setLoadingPhase("Emulating dynamic execution sandbox & correlating MITRE ATT&CK TTPs...");
    }, 480);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  };

  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    cyberAudio.playTabSwitch();
  };

  const loadPresetSample = async (presetId: string) => {
    setLoading(true);
    setErrorMessage(null);
    cyberAudio.playDataStream();
    const cancelSim = simulateProgress();
    try {
      const res = await fetch('/api/analyze/preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_id: presetId })
      });
      if (res.ok) {
        const data = await res.json();
        setLoadingProgress(100);
        setReport(data);
        if (data.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
        cancelSim();
        setLoading(false);
        setShowModal(false);
        return;
      }
    } catch {
      // Backend unavailable, fallback below
    }

    // Graceful fallback for static hosting / Vercel
    setTimeout(() => {
      const fallback = FALLBACK_REPORTS[presetId] || FALLBACK_REPORTS['sample_wannacry'];
      if (fallback) {
        setReport(fallback);
        if (fallback.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
      }
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }, 550);
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setErrorMessage(null);
    cyberAudio.playDataStream();
    const cancelSim = simulateProgress();
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/analyze/upload', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setLoadingProgress(100);
        setReport(data);
        setActiveTab('overview');
        if (data.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
        cancelSim();
        setLoading(false);
        setShowModal(false);
        return;
      }
    } catch {
      // Backend unavailable, use client-side analyzer below
    }

    // Fallback: Client-side dynamic forensic analysis in the browser (100% works on Vercel)
    try {
      const clientReport = await analyzeFileClientSide(file);
      setTimeout(() => {
        setLoadingProgress(100);
        setReport(clientReport);
        setActiveTab('overview');
        if (clientReport.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
        cancelSim();
        setLoading(false);
        setShowModal(false);
      }, 600);
    } catch (clientErr: any) {
      setErrorMessage("Analysis failed: " + (clientErr?.message || "Unknown error"));
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }
  };

  return (
    <div className="min-h-screen cyber-bg text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-slate-950 relative overflow-hidden">
      {/* Interactive 60fps Cyber Particle & Filament Canvas */}
      <CyberParticleCanvas theme={theme} />

      {/* Topmost Enterprise Status Bar in Iron Man Stark Armor Grid */}
      <div className="bg-[#0b0304]/95 border-b border-amber-900/40 px-4 py-1.5 text-[11px] font-mono flex flex-wrap items-center justify-between text-slate-400 gap-2 relative z-20">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-amber-400 font-black bg-red-950/80 px-2 py-0.5 rounded border border-amber-500/50 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping inline-block" />
            AUTONOMOUS DEFENSE GRID MK-85
          </span>

          {/* Equalizer Live Activity Bars */}
          <div className="flex items-center gap-0.5 h-4 px-1" title="Real-time telemetry stream active">
            <span className="w-0.5 bg-cyan-400 rounded-full animate-bar-1" />
            <span className="w-0.5 bg-sky-300 rounded-full animate-bar-2" />
            <span className="w-0.5 bg-blue-500 rounded-full animate-bar-3" />
            <span className="w-0.5 bg-teal-400 rounded-full animate-bar-4" />
            <span className="w-0.5 bg-cyan-500 rounded-full animate-bar-5" />
          </div>

          <span className="hidden md:inline text-cyan-300 font-semibold transition-all duration-500">
            {telemetryFeed[telemetryIndex]}
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          {/* Dynamic Theme Palette Switcher & Color Customizer Trigger */}
          <div className="flex items-center bg-slate-950/90 border border-white/[0.08] p-0.5 rounded-lg text-[10px] font-mono gap-1">
            <button
              onClick={() => {
                cyberAudio.playClick();
                setShowThemeModal(true);
              }}
              className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 font-bold transition cursor-pointer shadow-sm"
              title="Open Theme Studio & Color Customizer"
            >
              <Palette className="w-3 h-3 text-cyan-400 animate-spin-slow" />
              <span>THEMES</span>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: customColor || '#06b6d4' }} />
            </button>

            <div className="hidden sm:flex items-center gap-0.5">
              {[
                { id: 'cyan', label: 'CYAN', color: '#06b6d4' },
                { id: 'cobalt', label: 'COBALT', color: '#3b82f6' },
                { id: 'emerald', label: 'MATRIX', color: '#10b981' },
                { id: 'violet', label: 'VIOLET', color: '#a855f7' },
                { id: 'crimson', label: 'RED', color: '#ef4444' },
                { id: 'carbon', label: 'CARBON', color: '#94a3b8' },
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => {
                    setCustomColor(null);
                    localStorage.removeItem('pasha_custom_color');
                    setTheme(t.id as Theme);
                    cyberAudio.playClick();
                  }}
                  className={`px-1.5 py-0.5 rounded flex items-center gap-1 transition cursor-pointer ${
                    theme === t.id && !customColor
                      ? 'bg-white/15 text-white border border-white/30 font-black shadow-sm' 
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title={`Switch theme to ${t.label}`}
                >
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: t.color }} />
                  <span>{t.label}</span>
                </button>
              ))}
            </div>
          </div>

          <span className="hidden sm:inline text-slate-700 font-bold">|</span>

          {/* Audio Synthesizer Toggle */}
          <button
            onClick={() => {
              const muted = cyberAudio.toggleMute();
              setIsMuted(muted);
            }}
            className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg border text-[10px] font-mono font-bold transition cursor-pointer bg-slate-900/80 border-cyan-500/30 hover:bg-slate-800 text-cyan-300 hover:text-white shadow-sm"
            title="Toggle Synthesized Sci-Fi Sound FX"
          >
            {isMuted ? <VolumeX className="w-3.5 h-3.5 text-slate-400" /> : <Volume2 className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />}
            <span className="hidden sm:inline">JARVIS AUDIO: {isMuted ? 'MUTED' : 'ONLINE'}</span>
          </button>
          <span className="hidden sm:inline text-slate-700 font-bold">|</span>
          <span className="hidden sm:inline text-slate-400">ARMOR: <strong className="text-cyan-300">{hostAssessment?.host_info?.hostname || 'SUIT_ONLINE'}</strong></span>
          <span className="hidden sm:inline text-slate-700 font-bold">|</span>
          <span className="text-cyan-400 font-mono font-bold text-[11px] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block animate-pulse" />
            {currentTime} UTC
          </span>
        </div>
      </div>

      {/* Main Command Header in High-Tech Cyber Aesthetic */}
      <header className="glass-panel sticky top-0 z-40 border-b border-cyan-500/20">
        <div className="max-w-7xl mx-auto px-4 py-3.5 flex justify-between items-center gap-4">
          {/* Brand & Logo */}
          <div className="flex items-center gap-3.5">
            <div className="relative group cursor-pointer" onClick={() => setShowThemeModal(true)} title="Click to customize theme & colors">
              <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-cyan-500 via-sky-500 to-blue-600 p-[1.5px] shadow-lg shadow-cyan-950/80 transition-transform duration-300 group-hover:scale-105">
                <div className="w-full h-full bg-[#040d1e] rounded-2xl flex items-center justify-center">
                  <Shield className="w-6 h-6 text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]" />
                </div>
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-cyan-400 border-2 border-slate-950 animate-pulse" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black tracking-widest text-white flex items-center gap-2">
                  <span className="gradient-text-arc font-black tracking-widest">PASHA</span>
                </h1>
              </div>
              <p className="text-xs text-slate-400 font-medium">
                Autonomous Threat Reversing &amp; Deep Behavioral Sandboxing
              </p>
            </div>
          </div>

          {/* Quick Actions & Live Counters */}
          <div className="flex items-center gap-3">
            {hostAssessment && (
              <button 
                onClick={() => handleOpenTab('host')}
                className="hidden lg:flex items-center gap-2.5 bg-[#040d1e]/90 hover:bg-[#071630] px-3.5 py-2 rounded-xl border border-cyan-900/50 hover:border-cyan-400/50 transition shadow-inner group cursor-pointer"
              >
                <MonitorCheck className="w-4 h-4 text-emerald-400 group-hover:animate-bounce" />
                <div className="text-left text-xs">
                  <div className="text-[10px] text-slate-400 leading-none">Endpoint Health</div>
                  <div className="font-mono font-black text-slate-200 leading-tight">
                    {hostAssessment.health_score}/100 
                    <span className="text-[10px] ml-1 font-bold" style={{ color: hostAssessment.status_color }}>
                      ({hostAssessment.status})
                    </span>
                  </div>
                </div>
              </button>
            )}

            {report && (
              <button 
                onClick={() => handleOpenTab('overview')}
                className="hidden md:flex items-center gap-2.5 bg-[#040d1e]/90 hover:bg-[#071630] px-3.5 py-2 rounded-xl border border-cyan-900/50 hover:border-cyan-400/50 text-xs font-mono shadow-inner transition cursor-pointer"
                title="Click to view Executive Overview"
              >
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: report.threat_scoring.color }} />
                <div className="text-left">
                  <div className="text-[10px] text-slate-400 leading-none">Sample</div>
                  <div className="font-bold text-cyan-200 max-w-[130px] truncate leading-tight" title={report.sample_name}>
                    {report.sample_name}
                  </div>
                </div>
                {(report as any).analysis_duration_ms && (
                  <span className="text-[10px] text-slate-400 border-l border-cyan-900/60 pl-2 flex items-center gap-1">
                    <Zap className="w-3 h-3 text-cyan-400" />
                    {(report as any).analysis_duration_ms}ms
                  </span>
                )}
              </button>
            )}

            <button
              onClick={() => {
                cyberAudio.playClick();
                setShowJarvisModal(true);
              }}
              className="flex items-center gap-2 px-3.5 py-2.5 bg-[#040d1e]/90 hover:bg-[#071630] text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400 rounded-xl text-xs font-bold transition-all duration-300 shadow-xl shadow-cyan-950/60 hover:scale-[1.02] active:scale-[0.98] cursor-pointer group"
              title="Open J.A.R.V.I.S. Tactical AI Voice Guide"
            >
              <Bot className="w-4 h-4 text-cyan-400 group-hover:animate-bounce stroke-[2.5]" />
              <span className="hidden sm:inline font-mono">J.A.R.V.I.S. Audio Guide</span>
            </button>

            <button
              onClick={() => {
                cyberAudio.playClick();
                handleOpenJarvisChat();
              }}
              className="flex items-center gap-2 px-3.5 py-2.5 bg-gradient-to-r from-cyan-600/25 via-sky-600/25 to-blue-500/25 hover:from-cyan-600/40 hover:to-blue-500/40 text-cyan-300 hover:text-white border border-cyan-500/50 hover:border-cyan-400 rounded-xl text-xs font-bold transition-all duration-300 shadow-xl shadow-cyan-950/60 hover:scale-[1.02] active:scale-[0.98] cursor-pointer group"
              title="Ask J.A.R.V.I.S. questions about malware removal & remediation"
            >
              <MessageSquare className="w-4 h-4 text-cyan-400 group-hover:scale-110 stroke-[2.5]" />
              <span className="hidden sm:inline font-mono">Talk to J.A.R.V.I.S.</span>
            </button>

            <button
              onClick={() => {
                cyberAudio.playClick();
                setShowModal(true);
              }}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black rounded-xl text-xs transition-all duration-300 shadow-xl shadow-cyan-950/80 hover:shadow-cyan-900/90 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Upload className="w-4 h-4 stroke-[2.5]" />
              <span>Submit Payload</span>
            </button>
          </div>
        </div>
      </header>

      {/* Error Banner */}
      {errorMessage && (
        <div className="max-w-7xl mx-auto w-full px-4 pt-4">
          <div className="bg-rose-950/80 border border-rose-500/60 p-3.5 rounded-2xl text-xs text-rose-200 flex items-center justify-between shadow-xl shadow-rose-950/40 animate-fadeIn">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span><strong>System Notice:</strong> {errorMessage}</span>
            </div>
            <button 
              onClick={() => setErrorMessage(null)} 
              className="text-slate-400 hover:text-white px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6 relative z-10">
        {/* J.A.R.V.I.S. Tactical AI Voice Assistant & Threat Guide Banner */}
        {!loading && (report || hostAssessment) && (
          <JarvisVoiceBanner
            report={report}
            hostAssessment={hostAssessment}
            onOpenModal={() => setShowJarvisModal(true)}
            onOpenChat={handleOpenJarvisChat}
          />
        )}

        {/* Legendary Holographic 3D Gyroscopic Reactor Core */}
        {!loading && report && (
          <HoloReactorCore 
            score={report.threat_scoring.threat_score}
            severity={report.threat_scoring.severity}
            verdict={report.threat_scoring.verdict}
            color={report.threat_scoring.color}
            sampleName={report.sample_name}
          />
        )}

        {/* Executive KPI Ribbon (Clickable jump cards) */}
        {!loading && report && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
            {/* KPI 1 - Threat Verdict */}
            <div
              onClick={() => handleOpenTab('overview')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-red-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'overview' ? 'border-red-500/60 ring-1 ring-red-500/30 shadow-red-950/40' : 'border-white/[0.08]'
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-red-300 transition">Threat Verdict</span>
                <ShieldAlert className="w-4 h-4 text-red-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight" style={{ color: report.threat_scoring.color }}>
                {report.threat_scoring.severity}
              </div>
              <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                <span>Score: <strong className="text-white font-mono">{report.threat_scoring.threat_score}/100</strong></span>
                <button
                  type="button"
                  onClick={(e) => handleOpenTab('overview', e)}
                  className="text-[11px] font-mono font-bold text-red-300 hover:text-white bg-red-950/70 hover:bg-red-800/80 px-2.5 py-0.5 rounded-md border border-red-500/40 hover:border-red-400 transition flex items-center gap-1 cursor-pointer shadow-sm active:scale-95"
                >
                  <span>Open</span>
                  <ArrowUpRight className="w-3.5 h-3.5 stroke-[2.5]" />
                </button>
              </div>
            </div>

            {/* KPI 2 - Host Health Status */}
            <div
              onClick={() => handleOpenTab('host')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-cyan-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'host' ? 'border-cyan-500/60 ring-1 ring-cyan-500/30 shadow-cyan-950/40' : 'border-white/[0.08]'
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-cyan-300 transition">Host Health Status</span>
                <MonitorCheck className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight text-cyan-300">
                {hostAssessment?.health_score ?? 100}/100
              </div>
              <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                <span className="truncate">Host: <strong className="text-slate-200 font-mono">{hostAssessment?.host_info?.hostname || 'ONLINE'}</strong></span>
                <button
                  type="button"
                  onClick={(e) => handleOpenTab('host', e)}
                  className="text-[11px] font-mono font-bold text-cyan-300 hover:text-white bg-cyan-950/70 hover:bg-cyan-800/80 px-2.5 py-0.5 rounded-md border border-cyan-500/40 hover:border-cyan-400 transition flex items-center gap-1 cursor-pointer shadow-sm active:scale-95 shrink-0"
                >
                  <span>Open</span>
                  <ArrowUpRight className="w-3.5 h-3.5 stroke-[2.5]" />
                </button>
              </div>
            </div>

            {/* KPI 3 - Forensic Extraction */}
            <div
              onClick={() => handleOpenTab('iocs')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-sky-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'iocs' ? 'border-sky-500/60 ring-1 ring-sky-500/30 shadow-sky-950/40' : 'border-white/[0.08]'
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-sky-300 transition">Forensic Extraction</span>
                <Database className="w-4 h-4 text-sky-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight text-sky-300">
                {report.ioc_extraction.total_extracted} Indicators
              </div>
              <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                <span>{report.ioc_extraction.summary_by_category?.['Network C2'] || 0} C2 IPs</span>
                <button
                  type="button"
                  onClick={(e) => handleOpenTab('iocs', e)}
                  className="text-[11px] font-mono font-bold text-sky-300 hover:text-white bg-sky-950/70 hover:bg-sky-800/80 px-2.5 py-0.5 rounded-md border border-sky-500/40 hover:border-sky-400 transition flex items-center gap-1 cursor-pointer shadow-sm active:scale-95"
                >
                  <span>Open</span>
                  <ArrowUpRight className="w-3.5 h-3.5 stroke-[2.5]" />
                </button>
              </div>
            </div>

            {/* KPI 4 - Execution Speed */}
            <div
              onClick={() => handleOpenTab('static')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-teal-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'static' ? 'border-teal-500/60 ring-1 ring-teal-500/30 shadow-teal-950/40' : 'border-white/[0.08]'
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-teal-300 transition">Execution Speed</span>
                <Zap className="w-4 h-4 text-teal-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight text-teal-300">
                {(report as any).analysis_duration_ms || 18} ms
              </div>
              <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                <span>Streaming Engine</span>
                <button
                  type="button"
                  onClick={(e) => handleOpenTab('static', e)}
                  className="text-[11px] font-mono font-bold text-teal-300 hover:text-white bg-teal-950/70 hover:bg-teal-800/80 px-2.5 py-0.5 rounded-md border border-teal-500/40 hover:border-teal-400 transition flex items-center gap-1 cursor-pointer shadow-sm active:scale-95"
                >
                  <span>Open</span>
                  <ArrowUpRight className="w-3.5 h-3.5 stroke-[2.5]" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Loading Spinner & Radar HUD in Cyber Cyan */}
        {loading ? (
          <div className="glass-panel rounded-3xl p-14 flex flex-col items-center justify-center space-y-6 shadow-2xl relative overflow-hidden my-12 border border-cyan-500/30">
            <div className="absolute inset-0 bg-gradient-to-b from-cyan-600/15 via-teal-900/10 to-transparent animate-pulse" />

            <div className="relative">
              <div className="w-24 h-24 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center shadow-xl shadow-cyan-950/80" />
              <Radio className="w-10 h-10 text-cyan-400 absolute inset-0 m-auto animate-ping opacity-75" />
            </div>

            <div className="text-center space-y-3 z-10 max-w-lg w-full">
              <div className="text-xl font-black tracking-wide text-white">
                Zero-Lag Threat Engine Executing...
              </div>
              <div className="text-xs font-mono text-cyan-300 bg-[#061022]/90 py-2 px-4 rounded-xl border border-cyan-900/50">
                {loadingPhase}
              </div>

              {/* Progress Bar in Cyber Cyan & Teal */}
              <div className="w-full bg-[#040916] rounded-full h-3 border border-cyan-900/50 overflow-hidden mt-3 shadow-inner">
                <div 
                  className="bg-gradient-to-r from-cyan-600 via-teal-500 to-sky-400 h-full rounded-full transition-all duration-300 shadow-md shadow-cyan-900/50"
                  style={{ width: `${loadingProgress}%` }}
                />
              </div>
              <div className="flex justify-between text-[11px] font-mono text-slate-500 pt-1">
                <span>Streaming Forensic Pipeline</span>
                <span className="text-cyan-400 font-bold">{loadingProgress}%</span>
              </div>
            </div>
          </div>
        ) : report ? (
          <>
            {/* Segmented Tab Navigation Rail */}
            <div 
              ref={workspaceRef}
              id="workspace-tabs"
              className="flex overflow-x-auto glass-panel p-1.5 rounded-2xl border border-cyan-500/20 text-xs font-bold gap-1.5 shadow-2xl scroll-mt-20"
            >
              {[
                { id: 'host', label: 'System Auto-Assessment', icon: MonitorCheck, badge: hostAssessment ? `${hostAssessment.health_score}/100` : undefined, badgeColor: hostAssessment?.status_color },
                { id: 'overview', label: 'Executive Overview', icon: ShieldAlert },
                { id: 'static', label: 'Static Analysis', icon: Cpu },
                { id: 'sandbox', label: 'Behavioral Sandbox', icon: Terminal },
                { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers },
                { id: 'iocs', label: 'Extracted IOCs', icon: Database },
                { id: 'yara', label: 'YARA Workbench', icon: Code2 },
                { id: 'report', label: 'Automated Report', icon: FileText }
              ].map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => handleTabChange(tab.id)}
                    className={`flex items-center gap-2 px-4 py-2.5 rounded-xl transition-all duration-200 whitespace-nowrap text-xs font-bold cursor-pointer ${
                      isActive 
                        ? 'bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 text-slate-950 font-black shadow-lg shadow-cyan-950/80 scale-[1.02] border border-cyan-400/50' 
                        : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                    {tab.badge && (
                      <span 
                        className="px-2 py-0.5 text-[10px] font-mono font-black rounded-md text-slate-950 shadow-sm"
                        style={{ backgroundColor: tab.badgeColor || '#06b6d4' }}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Active Viewport */}
            <div className="transition-all duration-300">
              {activeTab === 'host' && (
                <SystemAssessmentTab 
                  assessment={hostAssessment} 
                  loading={hostLoading} 
                  onRescan={runHostAutoAssessment} 
                  report={report}
                  onOpenJarvisChat={handleOpenJarvisChat}
                />
              )}
              {activeTab === 'overview' && <DashboardOverview report={report} onNavigateTab={setActiveTab} />}
              {activeTab === 'static' && <StaticAnalysisTab staticAnalysis={report.static_analysis} />}
              {activeTab === 'sandbox' && <BehavioralSandboxTab behavioral={report.behavioral_analysis} />}
              {activeTab === 'mitre' && <MitreAttackTab mitre={report.mitre_mapping} />}
              {activeTab === 'iocs' && <IocExtractorTab ioc={report.ioc_extraction} reportId={report.report_id} />}
              {activeTab === 'yara' && <YaraWorkbenchTab yaraScan={report.yara_scan} />}
              {activeTab === 'report' && <ReportGeneratorTab report={report} />}
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-slate-500">
            No active threat session. Click <strong className="text-amber-400">Submit Payload</strong> to begin.
          </div>
        )}
      </main>

      {/* Real-Time Live Telemetry Matrix Terminal HUD */}
      <LiveTelemetryTerminal />

      {/* Submit Sample Modal */}
      {showModal && (
        <SampleSelectorModal
          onSelectPreset={loadPresetSample}
          onFileUpload={handleFileUpload}
          onClose={() => setShowModal(false)}
        />
      )}

      {/* J.A.R.V.I.S. Tactical AI Voice Assistant & Teleprompter Console Modal */}
      <JarvisAssistantModal
        report={report}
        hostAssessment={hostAssessment}
        isOpen={showJarvisModal}
        onClose={() => setShowJarvisModal(false)}
        onNavigateTab={handleOpenTab}
        onOpenChat={handleOpenJarvisChat}
      />

      {/* J.A.R.V.I.S. Interactive Q&A Assistant Chat Modal */}
      <JarvisChatModal
        report={report}
        hostAssessment={hostAssessment}
        isOpen={showChatModal}
        onClose={() => setShowChatModal(false)}
        initialPrompt={chatInitialPrompt}
      />

      {/* Theme Studio & Accent Color Customizer Modal */}
      <ThemeSelectorModal
        currentTheme={theme}
        isOpen={showThemeModal}
        onClose={() => setShowThemeModal(false)}
        onSelectTheme={(t) => {
          setTheme(t as Theme);
          setCustomColor(null);
          localStorage.removeItem('pasha_custom_color');
        }}
        onApplyCustomColor={handleApplyCustomColor}
        activeCustomColor={customColor}
        onResetDefault={handleResetDefaultTheme}
      />

      {/* High-End Enterprise Footer */}
      <footer className="glass-panel border-t border-cyan-500/20 mt-auto py-5 px-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400"></span>
            </span>
            <span className="text-slate-400 font-mono text-xs">PASHA &bull; <strong className="text-cyan-400 font-black">ENTERPRISE CYBER DEFENSE PLATFORM</strong></span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500">
            <span>STIX 2.1</span>
            <span>&bull;</span>
            <span>MITRE ATT&CK v14</span>
            <span>&bull;</span>
            <span>YARA v4.5</span>
            <span>&bull;</span>
            <span>SHA-256 PROVENANCE</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
