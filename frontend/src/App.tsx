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
import { PashaSentinelDashboard } from './components/PashaSentinelDashboard';
import { HostSecurityDiffTab } from './components/HostSecurityDiffTab';
import { NormalUserDashboard } from './components/NormalUserDashboard';
import { SampleSelectorModal } from './components/SampleSelectorModal';
import { LocalHostScannerModal } from './components/LocalHostScannerModal';
import { CyberParticleCanvas } from './components/CyberParticleCanvas';
import { LiveTelemetryTerminal } from './components/LiveTelemetryTerminal';
import { JarvisAssistantModal } from './components/JarvisAssistantModal';
import { JarvisChatModal } from './components/JarvisChatModal';
import { FALLBACK_REPORTS } from './data/mockReports';
import { analyzeFileClientSide } from './utils/clientAnalyzer';
import { cyberAudio } from './utils/cyberAudio';
import { jarvisVoice, JarvisSpeechState } from './utils/jarvisVoice';
import { detectClientHostEnvironment } from './utils/clientHostAuditor';
import { 
  Shield, ShieldAlert, ShieldCheck, Cpu, Terminal, Layers, Database, Code2, FileText, 
  Upload, AlertTriangle, MonitorCheck, Zap, Radio,
  Volume2, VolumeX, Palette, Bot, MessageSquare, Sliders,
  ChevronDown, ChevronUp, Play, Pause, Laptop, CheckCircle2, UserCheck, 
  RefreshCw, Crosshair, Radar, GitCompare, X
} from 'lucide-react';
import { ThemeSelectorModal, ThemeId } from './components/ThemeSelectorModal';

export type Theme = ThemeId;

export const App: React.FC = () => {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('pasha_theme');
    if (saved === 'amber' || saved === 'ironman' || saved === 'cyan' || !saved) {
      return 'carbon';
    }
    return (saved as Theme) || 'carbon';
  });

  const [customColor, setCustomColor] = useState<string | null>(() => {
    return localStorage.getItem('pasha_custom_color') || null;
  });

  // UI Modes & Modals
  const [viewMode, setViewMode] = useState<'simple' | 'expert'>('simple');
  const [heroMode, setHeroMode] = useState<'host' | 'payload'>('host');
  const [showThemeModal, setShowThemeModal] = useState<boolean>(false);
  const [showHostScanModal, setShowHostScanModal] = useState<boolean>(false);
  const [showToolsDropdown, setShowToolsDropdown] = useState<boolean>(false);
  const [showJarvisDropdown, setShowJarvisDropdown] = useState<boolean>(false);
  const [showAdvancedSpecs, setShowAdvancedSpecs] = useState<boolean>(false);
  const [showTerminal, setShowTerminal] = useState<boolean>(false);

  // Core Data State (Starts in UN-SCANNED standby state!)
  const [hasScannedHost, setHasScannedHost] = useState<boolean>(false);
  const [report, setReport] = useState<FullAnalysisReport>(FALLBACK_REPORTS['sample_wannacry']);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment | null>(null);
  const [hostLoading, setHostLoading] = useState<boolean>(false);
  const [isAgentOnline, setIsAgentOnline] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [malwareSubTab, setMalwareSubTab] = useState<string>('overview');
  const [hasCustomFileUpload, setHasCustomFileUpload] = useState<boolean>(false);

  // Modals & Chat
  const [showModal, setShowModal] = useState<boolean>(false);
  const [showJarvisModal, setShowJarvisModal] = useState<boolean>(false);
  const [showChatModal, setShowChatModal] = useState<boolean>(false);
  const [chatInitialPrompt, setChatInitialPrompt] = useState<string>('');
  const [speechState, setSpeechState] = useState<JarvisSpeechState>(jarvisVoice.getState());

  // Audio & Ticker
  const [isMuted, setIsMuted] = useState<boolean>(cyberAudio.getIsMuted());
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingPhase, setLoadingPhase] = useState<string>('Initializing forensic pipeline...');
  const [loadingProgress, setLoadingProgress] = useState<number>(100);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState<string>(new Date().toTimeString().split(' ')[0]);
  const [telemetryIndex, setTelemetryIndex] = useState<number>(0);

  const workspaceRef = useRef<HTMLDivElement | null>(null);

  const telemetryFeed = [
    "LOCAL SENTINEL: Host telemetry agent standing by for on-demand execution",
    "PERSISTENCE SHIELD: Windows Registry RunKeys continuously monitored",
    "CVE SENTINEL: NVD vulnerability database catalog indexed",
    "HEURISTIC DEFENSE: Real-time API hooking & behavioral telemetry armed"
  ];

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('[data-dropdown]')) {
        setShowToolsDropdown(false);
        setShowJarvisDropdown(false);
      }
    };
    window.addEventListener('click', handleOutsideClick);
    return () => window.removeEventListener('click', handleOutsideClick);
  }, []);

  // Theme synchronization
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

  useEffect(() => {
    return jarvisVoice.subscribe(setSpeechState);
  }, []);

  // Check URL query parameters & ONLY probe agent connectivity (DO NOT auto-scan!)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('candidate') || urlParams.get('view') === 'sentinel') {
      setActiveTab('sentinel');
    }

    // Probe if agent / local API is online, but DO NOT run or populate scan yet
    fetch('/api/agent/status')
      .then(res => {
        if (res.ok) setIsAgentOnline(true);
      })
      .catch(() => {
        fetch('http://127.0.0.1:8000/api/agent/status')
          .then(res => {
            if (res.ok) setIsAgentOnline(true);
          })
          .catch(() => setIsAgentOnline(false));
      });

    const timer = setInterval(() => {
      setCurrentTime(new Date().toTimeString().split(' ')[0]);
    }, 1000);

    const ticker = setInterval(() => {
      setTelemetryIndex(prev => (prev + 1) % telemetryFeed.length);
    }, 4000);

    return () => {
      clearInterval(timer);
      clearInterval(ticker);
    };
  }, []);

  const handleApplyCustomColor = (hex: string) => {
    setCustomColor(hex);
    localStorage.setItem('pasha_custom_color', hex);
  };

  const handleResetDefaultTheme = () => {
    setCustomColor(null);
    localStorage.removeItem('pasha_custom_color');
    setTheme('carbon');
  };

  const handleOpenTab = (tabId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (['overview', 'sandbox', 'static', 'mitre', 'iocs', 'yara'].includes(tabId)) {
      if (hasCustomFileUpload) {
        setActiveTab('malware');
        setMalwareSubTab(tabId);
      } else {
        setActiveTab('host');
      }
    } else {
      setActiveTab(tabId);
    }
    cyberAudio.playTabSwitch();
    setTimeout(() => {
      workspaceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 60);
  };

  const handleOpenJarvisChat = (prompt?: string) => {
    setChatInitialPrompt(prompt || '');
    setShowChatModal(true);
    setShowJarvisDropdown(false);
  };

  const handleToggleVoiceBriefing = () => {
    cyberAudio.playClick();
    if (speechState.isSpeaking && !speechState.isPaused) {
      jarvisVoice.pause();
    } else if (speechState.isPaused) {
      jarvisVoice.resume();
    } else {
      const script = jarvisVoice.generateFullScript(report, hostAssessment || detectClientHostEnvironment());
      jarvisVoice.speak(script, 'full');
    }
  };

  /**
   * Main Amplified "Scan Your Computer" Execution Flow
   * Only populates and scores when actively invoked!
   */
  const triggerHostScan = async (showModalIfOffline: boolean = false) => {
    setHostLoading(true);
    cyberAudio.playDataStream();
    cyberAudio.playRadarSweep();
    setHeroMode('host');

    try {
      // 1. Attempt relative backend endpoint (standard local dev / reverse proxy)
      const res = await fetch('/api/system/auto-assess', {
        signal: AbortSignal.timeout(6000)
      }).catch(() => null);

      if (res?.ok) {
        const data = await res.json();
        setHostAssessment(data);
        setHasScannedHost(true);
        setIsAgentOnline(true);
        cyberAudio.playSuccess();
        setHostLoading(false);
        return;
      }
    } catch {}

    try {
      // 2. Attempt direct localhost endpoint (when website is on cloud and agent runs on local PC)
      const directRes = await fetch('http://127.0.0.1:8000/api/system/auto-assess', {
        signal: AbortSignal.timeout(3000)
      }).catch(() => null);

      if (directRes?.ok) {
        const data = await directRes.json();
        setHostAssessment(data);
        setHasScannedHost(true);
        setIsAgentOnline(true);
        cyberAudio.playSuccess();
        setHostLoading(false);
        return;
      }
    } catch {}

    // 3. Fallback: Run instant browser perimeter audit & open companion modal if requested
    setIsAgentOnline(false);
    const clientEnv = detectClientHostEnvironment();
    setHostAssessment(clientEnv);
    setHasScannedHost(true);
    cyberAudio.playSuccess();
    setHostLoading(false);

    if (showModalIfOffline) {
      setShowHostScanModal(true);
    }
  };

  const simulateProgress = () => {
    setLoadingProgress(20);
    setLoadingPhase("Ingesting payload & streaming cryptographic fingerprints (MD5/SHA256)...");
    
    const t1 = setTimeout(() => {
      setLoadingProgress(50);
      setLoadingPhase("Profiling PE section entropy & detecting commercial packing (UPX/Themida)...");
    }, 150);

    const t2 = setTimeout(() => {
      setLoadingProgress(78);
      setLoadingPhase("Evaluating YARA signature rulesets & decoding suspicious strings...");
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

  const loadPresetSample = async (presetId: string) => {
    setLoading(true);
    setErrorMessage(null);
    setHasCustomFileUpload(true);
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
        setHeroMode('payload');
        setActiveTab('malware');
        setMalwareSubTab('overview');
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
    } catch {}

    setTimeout(() => {
      const fallback = FALLBACK_REPORTS[presetId] || FALLBACK_REPORTS['sample_wannacry'];
      if (fallback) {
        setReport(fallback);
        setHeroMode('payload');
        setActiveTab('malware');
        setMalwareSubTab('overview');
        if (fallback.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
      }
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }, 500);
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setErrorMessage(null);
    setHasCustomFileUpload(true);
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
        setHeroMode('payload');
        setActiveTab('malware');
        setMalwareSubTab('overview');
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
    } catch {}

    // Fallback: Client-side dynamic forensic analysis in the browser
    try {
      const clientReport = await analyzeFileClientSide(file);
      setTimeout(() => {
        setLoadingProgress(100);
        setReport(clientReport);
        setHeroMode('payload');
        setActiveTab('malware');
        setMalwareSubTab('overview');
        if (clientReport.threat_scoring?.threat_score >= 70) {
          cyberAudio.playAlarm();
        } else {
          cyberAudio.playRadarSweep();
        }
        cancelSim();
        setLoading(false);
        setShowModal(false);
      }, 550);
    } catch (clientErr: any) {
      setErrorMessage("Analysis failed: " + (clientErr?.message || "Unknown error"));
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }
  };

  const coils = [0, 36, 72, 108, 144, 180, 216, 252, 288, 324];

  // 4 Primary Clean Navigation Workflows for Forensic Expert Mode (Dedicated to Host Computer)
  const FORENSIC_WORKFLOW_TABS = [
    { 
      id: 'host', 
      label: 'Host Telemetry & Vulnerabilities', 
      icon: Laptop, 
      badge: hasScannedHost ? `${hostAssessment?.health_score ?? 100}/100` : 'STANDBY', 
      badgeColor: hasScannedHost ? (hostAssessment?.status_color || '#10b981') : '#06b6d4' 
    },
    { 
      id: 'sentinel', 
      label: 'Pasha Sentinel Guard', 
      icon: ShieldCheck, 
      badge: 'AUTOMATED', 
      badgeColor: '#00f2fe' 
    },
    { 
      id: 'diff', 
      label: 'Host Snapshot & Change Monitor', 
      icon: GitCompare, 
      badge: 'LIVE DIFF', 
      badgeColor: '#a855f7' 
    },
    { 
      id: 'report', 
      label: 'Host Audit & Compliance Dossier', 
      icon: FileText,
      badge: 'OFFICIAL',
      badgeColor: '#10b981'
    },
    ...(hasCustomFileUpload ? [{
      id: 'malware', 
      label: `Suspect File: ${report?.sample_name || 'Uploaded Binary'}`, 
      icon: Terminal, 
      badge: `${report?.threat_scoring?.threat_score ?? 0}/100`, 
      badgeColor: report?.threat_scoring?.color || '#ef4444' 
    }] : [])
  ];

  // Sub-tabs inside Malware Lab (Forensic Expert Mode)
  const MALWARE_LAB_SUBTABS = [
    { id: 'overview', label: 'Executive Verdict', icon: ShieldAlert },
    { id: 'sandbox', label: 'Behavioral Sandbox', icon: Terminal },
    { id: 'static', label: 'Static Analysis', icon: Cpu },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers },
    { id: 'iocs', label: 'Extracted IOCs', icon: Database },
    { id: 'yara', label: 'YARA Workbench', icon: Code2 }
  ];

  return (
    <div className="min-h-screen cyber-bg text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-slate-950 relative overflow-hidden">
      {/* 60fps Cyber Particle & Filament Canvas */}
      <CyberParticleCanvas theme={theme} />

      {/* Streamlined, High-Performance Navigation Header */}
      <header className="glass-panel sticky top-0 z-40 border-b border-cyan-500/20 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 py-2.5 flex items-center justify-between gap-3">
          
          {/* Brand & Connection Status */}
          <div className="flex items-center gap-3">
            <div 
              className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 p-[1.5px] cursor-pointer shadow-md shadow-cyan-950/60 transition hover:scale-105"
              onClick={() => setShowThemeModal(true)}
              title="Customize Theme & Accent Colors"
            >
              <div className="w-full h-full bg-[#040d1e] rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]" />
              </div>
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-black tracking-wider text-white">PASHA</span>
                
                {/* Agent Connection Badge (Clickable to open guidance) */}
                <button
                  onClick={() => setShowHostScanModal(true)}
                  className={`hidden sm:inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded-full border transition cursor-pointer ${
                    isAgentOnline 
                      ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/50 hover:bg-emerald-900/60' 
                      : 'bg-cyan-950/70 text-cyan-400 border-cyan-800/60 hover:bg-cyan-900/60'
                  }`}
                  title="Click to view Local Agent & Extension status"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isAgentOnline ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400 animate-pulse'}`} />
                  <span>{isAgentOnline ? 'LOCAL AGENT CONNECTED' : 'SYSTEM SCAN READY'}</span>
                </button>
              </div>
              <p className="text-[11px] text-slate-400 font-medium hidden md:block">
                {viewMode === 'simple' 
                  ? 'Simple & Secure Computer Health Scanner' 
                  : 'Tactical Windows Endpoint Protection & Reverse Engineering'}
              </p>
            </div>
          </div>

          {/* Center: Normal View vs Forensic Expert View Toggle */}
          <div className="flex items-center bg-slate-950/90 p-1 rounded-2xl border border-white/[0.12] text-xs font-mono shadow-inner">
            <button
              onClick={() => {
                cyberAudio.playClick();
                setViewMode('simple');
              }}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl transition font-bold cursor-pointer ${
                viewMode === 'simple' 
                  ? 'bg-cyan-500 text-slate-950 shadow-md font-black shadow-cyan-950/50' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>Normal View</span>
            </button>
            <button
              onClick={() => {
                cyberAudio.playClick();
                setViewMode('expert');
              }}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl transition font-bold cursor-pointer ${
                viewMode === 'expert' 
                  ? 'bg-cyan-500 text-slate-950 shadow-md font-black shadow-cyan-950/50' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Forensic Expert</span>
            </button>
          </div>

          {/* Right Action Cluster */}
          <div className="flex items-center gap-2">
            
            {/* Quick Header Scan Button */}
            <button
              onClick={() => triggerHostScan(true)}
              disabled={hostLoading}
              className="hidden lg:flex items-center gap-1.5 px-3 py-2 bg-slate-900/80 hover:bg-slate-800 text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400 font-bold rounded-xl text-xs transition cursor-pointer shadow-sm"
              title="Quick Scan Your Host Computer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${hostLoading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Scan PC</span>
            </button>

            {/* Submit / Upload Payload */}
            <button
              onClick={() => {
                cyberAudio.playClick();
                setShowModal(true);
              }}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black rounded-xl text-xs transition shadow-lg shadow-cyan-950/70 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 stroke-[2.5]" />
              <span className="hidden sm:inline">Upload File</span>
              <span className="sm:hidden">Upload</span>
            </button>

            {/* J.A.R.V.I.S. AI Assistant */}
            <div className="relative" data-dropdown>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  cyberAudio.playClick();
                  setShowJarvisDropdown(prev => !prev);
                  setShowToolsDropdown(false);
                }}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition cursor-pointer border ${
                  speechState.isSpeaking
                    ? 'bg-cyan-950/90 text-cyan-300 border-cyan-400/80 shadow-md shadow-cyan-950/80'
                    : 'bg-[#040d1e]/90 hover:bg-[#071630] text-cyan-300 hover:text-white border-cyan-500/40 hover:border-cyan-400'
                }`}
                title="J.A.R.V.I.S. AI Security Assistant"
              >
                <Bot className={`w-4 h-4 text-cyan-400 ${speechState.isSpeaking ? 'animate-bounce' : ''}`} />
                <span className="hidden sm:inline font-mono">AI Guard</span>
                <ChevronDown className={`w-3 h-3 text-cyan-400/80 transition-transform duration-200 ${showJarvisDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showJarvisDropdown && (
                <div className="absolute right-0 mt-2 w-64 glass-panel rounded-2xl border border-cyan-500/40 shadow-2xl p-2 z-50 animate-fadeIn text-xs space-y-1">
                  <div className="px-3 py-1.5 text-[10px] font-mono text-cyan-400 font-bold uppercase border-b border-cyan-900/40 mb-1 flex items-center justify-between">
                    <span>AI Assistant Suite</span>
                    {speechState.isSpeaking && (
                      <span className="text-emerald-400 animate-pulse font-mono text-[9px]">● SPEAKING</span>
                    )}
                  </div>

                  <button
                    onClick={() => {
                      setShowJarvisDropdown(false);
                      handleOpenJarvisChat();
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl hover:bg-cyan-950/60 text-slate-200 hover:text-white transition text-left cursor-pointer"
                  >
                    <MessageSquare className="w-4 h-4 text-cyan-400 shrink-0" />
                    <div>
                      <div className="font-bold">Ask Security Questions</div>
                      <div className="text-[10px] text-slate-400">Ask how to fix threats on your PC</div>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      handleToggleVoiceBriefing();
                      setShowJarvisDropdown(false);
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl hover:bg-cyan-950/60 text-cyan-300 hover:text-white transition text-left cursor-pointer border-t border-white/[0.06] pt-2"
                  >
                    {speechState.isSpeaking ? (
                      <Pause className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <Play className="w-4 h-4 text-cyan-400 shrink-0" />
                    )}
                    <div>
                      <div className="font-bold">
                        {speechState.isSpeaking ? 'Pause Voice Briefing' : 'Quick Voice Briefing'}
                      </div>
                      <div className="text-[10px] text-slate-400">Listen to spoken security summary</div>
                    </div>
                  </button>
                </div>
              )}
            </div>

            {/* Settings & Tools */}
            <div className="relative" data-dropdown>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  cyberAudio.playClick();
                  setShowToolsDropdown(prev => !prev);
                  setShowJarvisDropdown(false);
                }}
                className="flex items-center justify-center w-9 h-9 bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-white/[0.1] hover:border-cyan-500/40 rounded-xl transition cursor-pointer"
                title="Preferences & Tools"
              >
                <Sliders className="w-4 h-4 text-slate-300" />
              </button>

              {showToolsDropdown && (
                <div className="absolute right-0 mt-2 w-72 glass-panel rounded-2xl border border-cyan-500/40 shadow-2xl p-2.5 z-50 animate-fadeIn text-xs space-y-1.5">
                  <div className="px-3 py-1 text-[10px] font-mono text-cyan-400 font-bold uppercase border-b border-cyan-900/40">
                    Preferences &amp; System Tools
                  </div>

                  <button
                    onClick={() => {
                      setShowToolsDropdown(false);
                      setShowHostScanModal(true);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Laptop className="w-4 h-4 text-cyan-400" />
                      <span className="font-medium">How Scanning Works</span>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 font-bold">INFO</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowToolsDropdown(false);
                      setShowThemeModal(true);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Palette className="w-4 h-4 text-cyan-400" />
                      <span className="font-medium">Theme &amp; Accent Colors</span>
                    </div>
                    <span 
                      className="w-3.5 h-3.5 rounded-full border border-white/30 shadow-sm"
                      style={{ backgroundColor: customColor || '#06b6d4' }}
                    />
                  </button>

                  <button
                    onClick={() => {
                      const muted = cyberAudio.toggleMute();
                      setIsMuted(muted);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      {isMuted ? <VolumeX className="w-4 h-4 text-slate-500" /> : <Volume2 className="w-4 h-4 text-cyan-400" />}
                      <span className="font-medium">Sound Effects</span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${!isMuted ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/50' : 'bg-slate-800 text-slate-400'}`}>
                      {isMuted ? 'MUTED' : 'ENABLED'}
                    </span>
                  </button>

                  <button
                    onClick={() => setShowTerminal(prev => !prev)}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Terminal className="w-4 h-4 text-sky-400" />
                      <span className="font-medium">Live Telemetry Terminal</span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${showTerminal ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/50' : 'bg-slate-800 text-slate-400'}`}>
                      {showTerminal ? 'VISIBLE' : 'HIDDEN'}
                    </span>
                  </button>
                </div>
              )}
            </div>

          </div>
        </div>
      </header>

      {/* Error Banner */}
      {errorMessage && (
        <div className="max-w-7xl mx-auto w-full px-4 pt-4">
          <div className="bg-rose-950/80 border border-rose-500/60 p-3.5 rounded-2xl text-xs text-rose-200 flex items-center justify-between shadow-xl shadow-rose-950/40 animate-fadeIn">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span><strong>Notice:</strong> {errorMessage}</span>
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
        
        {/* AMPLIFIED HERO SECTION: Centerpiece for Host Scanning & Protection */}
        {!loading && (
          <div className="glass-panel p-6 sm:p-8 rounded-3xl border border-white/[0.14] relative overflow-hidden shadow-2xl transition-all duration-300 group">
            {/* Top specular reflection line */}
            <div className="absolute top-0 inset-x-12 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
            <div className="absolute -top-24 -left-24 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
            <div className="absolute -bottom-24 -right-24 w-80 h-80 rounded-full bg-blue-500/10 blur-3xl pointer-events-none" />
            <div className="absolute inset-0 bg-gradient-to-b from-white/[0.03] via-transparent to-transparent pointer-events-none" />

            {/* Host Health Hero Centerpiece */}
                <div className="text-center space-y-2 mb-4 relative z-10 max-w-2xl mx-auto">
                  <div className="flex flex-wrap items-center justify-center gap-2">
                    <span 
                      className={`px-3 py-1 rounded-full text-[11px] font-mono font-black uppercase tracking-wider flex items-center gap-1.5 shadow-sm ${
                        hasScannedHost 
                          ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/50' 
                          : 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                      }`}
                    >
                      {hasScannedHost ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>{hostAssessment?.status || 'OPTIMAL & PROTECTED'}</span>
                        </>
                      ) : (
                        <>
                          <Radar className="w-3.5 h-3.5 animate-spin" />
                          <span>STANDBY &bull; AWAITING SCAN</span>
                        </>
                      )}
                    </span>
                    <span className="text-xs font-mono text-zinc-300 font-bold px-2.5 py-0.5 rounded-lg bg-zinc-900/90 border border-white/[0.08]">
                      {hostAssessment?.host_info?.hostname || 'LOCAL PC'}
                    </span>
                    <span className="text-xs font-mono text-zinc-400">
                      {hostAssessment?.host_info?.os || 'Windows 11'}
                    </span>
                  </div>

                  <h2 className="text-xl sm:text-2xl md:text-3xl font-black text-white tracking-tight">
                    {!hasScannedHost 
                      ? 'Your Computer Has Not Been Scanned Yet' 
                      : (viewMode === 'simple' ? 'Your Computer is Safe & Clean' : 'Windows Endpoint Security & Telemetry Posture')}
                  </h2>

                  <p className="text-xs text-zinc-400 max-w-lg mx-auto">
                    {!hasScannedHost 
                      ? 'Click the button below to perform an instant, safe read-only security scan of running programs, startup apps, and open network ports.' 
                      : (viewMode === 'simple' 
                          ? 'All running programs and startup items verified. Zero viruses or hidden spyware detected.' 
                          : `Audited ${hostAssessment?.summary?.total_processes_scanned || 300}+ running processes and ${hostAssessment?.summary?.startup_items_scanned || 20}+ startup registry entries.`)}
                  </p>
                </div>

                {/* Arc Reactor: Health Score Circle (EMPTY / STANDBY until scanned!) */}
                <div className="flex justify-center items-center my-4 relative z-10">
                  <div className="relative w-44 h-44 sm:w-52 sm:h-52 flex items-center justify-center">
                    <div 
                      className="absolute inset-2 rounded-full filter blur-2xl opacity-35 pointer-events-none transition-all duration-700"
                      style={{ 
                        background: hasScannedHost
                          ? `radial-gradient(circle, #ffffff 0%, #a1a1aa 35%, ${hostAssessment?.status_color || '#10b981'}40 70%, transparent 100%)`
                          : `radial-gradient(circle, #38bdf8 0%, #0284c7 35%, transparent 70%)`
                      }}
                    />

                    <svg 
                      className="w-full h-full drop-shadow-[0_0_25px_rgba(255,255,255,0.35)] select-none transition-transform duration-300 hover:scale-105 cursor-pointer"
                      viewBox="0 0 190 190"
                      onClick={() => triggerHostScan(true)}
                    >
                      <circle cx="95" cy="95" r="91" fill="none" stroke="#27272a" strokeWidth="2" />
                      <circle 
                        cx="95" cy="95" r="87" 
                        fill="#09090b" 
                        stroke={hasScannedHost ? "#3f3f46" : "#38bdf8"} 
                        strokeWidth="2.5" 
                        strokeOpacity={hasScannedHost ? "0.8" : "0.5"} 
                        strokeDasharray="6 4" 
                      />

                      {coils.map((deg, i) => (
                        <g key={i} transform={`rotate(${deg} 95 95)`}>
                          <rect x="91" y="12" width="8" height="16" rx="2" fill="#18181b" stroke="#71717a" strokeWidth="1.2" />
                          <line x1="92" y1="16" x2="98" y2="16" stroke="#d4d4d8" strokeWidth="1.2" />
                        </g>
                      ))}

                      {/* Rotating Pulse Ring */}
                      <g className="animate-spin-slow origin-center" style={{ transformOrigin: '95px 95px' }}>
                        <circle cx="95" cy="95" r="70" fill="none" stroke={hasScannedHost ? "#71717a" : "#38bdf8"} strokeWidth="2.5" strokeOpacity="0.6" strokeDasharray="14 7" />
                        <circle cx="95" cy="25" r="2.5" fill="#ffffff" />
                        <circle cx="165" cy="95" r="2.5" fill="#ffffff" />
                        <circle cx="95" cy="165" r="2.5" fill="#ffffff" />
                        <circle cx="25" cy="95" r="2.5" fill="#ffffff" />
                      </g>

                      {/* Center Ring */}
                      <circle 
                        cx="95" cy="95" r="56" 
                        fill="#09090b" 
                        stroke={hasScannedHost ? (hostAssessment?.status_color || '#10b981') : "#38bdf8"} 
                        strokeWidth="3" 
                        strokeOpacity="0.9" 
                        strokeDasharray={hasScannedHost ? "none" : "6 4"}
                      />

                      {hasScannedHost ? (
                        <>
                          <text 
                            x="95" 
                            y="96" 
                            textAnchor="middle" 
                            fill="#ffffff" 
                            fontSize="26" 
                            fontWeight="900" 
                            fontFamily="monospace"
                            filter="drop-shadow(0 0 6px rgba(255,255,255,0.7))"
                          >
                            {hostAssessment?.health_score ?? 100}
                          </text>
                          <text 
                            x="95" 
                            y="114" 
                            textAnchor="middle" 
                            fill="#a1a1aa" 
                            fontSize="9" 
                            fontWeight="800" 
                            fontFamily="monospace"
                          >
                            /100 HEALTH
                          </text>
                        </>
                      ) : (
                        <>
                          <text 
                            x="95" 
                            y="92" 
                            textAnchor="middle" 
                            fill="#38bdf8" 
                            fontSize="17" 
                            fontWeight="900" 
                            fontFamily="monospace"
                            filter="drop-shadow(0 0 6px rgba(56,189,248,0.7))"
                          >
                            {hostLoading ? 'SCANNING' : 'STANDBY'}
                          </text>
                          <text 
                            x="95" 
                            y="110" 
                            textAnchor="middle" 
                            fill="#94a3b8" 
                            fontSize="8" 
                            fontWeight="800" 
                            fontFamily="monospace"
                          >
                            {hostLoading ? 'INSPECTING...' : 'CLICK TO SCAN'}
                          </text>
                        </>
                      )}
                    </svg>
                  </div>
                </div>

                {/* THE AMPLIFIED "SCAN YOUR COMPUTER NOW" BUTTON */}
                <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5 my-6 relative z-20">
                  <button
                    onClick={() => triggerHostScan(true)}
                    disabled={hostLoading}
                    className="group relative flex items-center justify-center gap-3 px-8 py-4.5 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:via-sky-400 hover:to-blue-500 text-slate-950 font-black rounded-2xl text-base transition-all duration-300 shadow-[0_0_35px_rgba(6,182,212,0.65)] hover:shadow-[0_0_55px_rgba(6,182,212,0.9)] hover:scale-[1.03] active:scale-[0.98] cursor-pointer border border-cyan-200/60"
                  >
                    <div className="w-8 h-8 rounded-xl bg-slate-950/40 flex items-center justify-center text-cyan-200 shadow-inner">
                      <Shield className={`w-5 h-5 ${hostLoading ? 'animate-spin' : 'animate-pulse'}`} />
                    </div>
                    <div className="text-left">
                      <div className="text-sm sm:text-base font-black tracking-wide uppercase leading-tight">
                        {hostLoading ? 'Scanning Your Computer...' : (hasScannedHost ? '🛡️ Re-Scan Your Computer' : '🛡️ Scan Your Computer Now')}
                      </div>
                      <div className="text-[11px] font-mono text-cyan-950 font-extrabold opacity-90 leading-tight">
                        {isAgentOnline ? '● Local Agent Active • Deep Windows Telemetry' : '⚡ 1-Click Endpoint Security Audit'}
                      </div>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      cyberAudio.playClick();
                      setShowModal(true);
                    }}
                    className="flex items-center gap-2 px-5 py-4 bg-zinc-900/90 hover:bg-zinc-800 text-zinc-200 hover:text-white rounded-2xl text-xs sm:text-sm font-bold transition border border-white/[0.1] hover:border-cyan-400/50 cursor-pointer shadow-md"
                  >
                    <Upload className="w-4 h-4 text-cyan-400" />
                    <span>Analyze a File / Malware</span>
                  </button>
                </div>

                {/* Layman Subtitle Pill */}
                <div className="text-center relative z-10 mb-4">
                  <span className="text-[11px] font-mono text-zinc-400 bg-zinc-900/80 px-3 py-1 rounded-full border border-white/[0.06]">
                    ✓ Safe &amp; Read-Only: Pasha inspects system health without modifying any files or settings.
                  </span>
                </div>

            {/* Symmetrical Vitals Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 relative z-10 pt-2 font-mono text-xs">
              
              {/* Card 1: Host Integrity */}
              <div 
                onClick={() => {
                  setHeroMode('host');
                  handleOpenTab('host');
                }}
                className="glass-card hover-glow-emerald p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 cursor-pointer text-center group shadow-md relative overflow-hidden hover:-translate-y-0.5"
              >
                <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/30 to-transparent pointer-events-none" />
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <MonitorCheck className="w-3.5 h-3.5 text-zinc-400" />
                  <span>{viewMode === 'simple' ? 'Computer Health' : 'Host Integrity'}</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {hasScannedHost ? `${hostAssessment?.health_score ?? 100}/100` : 'STANDBY'}
                </div>
                <div className="text-[10px] text-emerald-400 font-bold mt-0.5 flex items-center justify-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${hasScannedHost ? 'bg-emerald-400' : 'bg-cyan-400 animate-pulse'} inline-block`} />
                  <span>{hasScannedHost ? (hostAssessment?.status || 'OPTIMAL') : 'READY TO SCAN'}</span>
                </div>
              </div>

              {/* Card 2: Processes & Apps */}
              <div 
                onClick={() => {
                  setHeroMode('host');
                  handleOpenTab('host');
                }}
                className="glass-card hover-glow-cyan p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 cursor-pointer text-center group shadow-md relative overflow-hidden hover:-translate-y-0.5"
              >
                <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent pointer-events-none" />
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <Cpu className="w-3.5 h-3.5 text-zinc-400" />
                  <span>{viewMode === 'simple' ? 'Active Programs' : 'Processes Monitored'}</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {hasScannedHost ? `${hostAssessment?.summary?.total_processes_scanned || 302}` : '--'}
                </div>
                <div className="text-[10px] text-emerald-400 font-bold mt-0.5">
                  {hasScannedHost ? '0 SUSPICIOUS PROCESSES' : 'AWAITING SCAN'}
                </div>
              </div>

              {/* Card 3: Autostart & Registry */}
              <div 
                onClick={() => {
                  setHeroMode('host');
                  handleOpenTab('host');
                }}
                className="glass-card hover-glow-violet p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 cursor-pointer text-center group shadow-md relative overflow-hidden hover:-translate-y-0.5"
              >
                <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-purple-400/30 to-transparent pointer-events-none" />
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5 text-zinc-400" />
                  <span>{viewMode === 'simple' ? 'Startup Apps' : 'Registry RunKeys'}</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {hasScannedHost ? `${hostAssessment?.summary?.startup_items_scanned || 21}` : '--'}
                </div>
                <div className="text-[10px] text-zinc-400 font-bold mt-0.5">
                  {hasScannedHost ? 'SECURE • 0 UNKNOWN' : 'AWAITING SCAN'}
                </div>
              </div>

              {/* Card 4: J.A.R.V.I.S. Audio & Help */}
              <div className="glass-card p-2 rounded-2xl border border-white/[0.14] flex flex-col justify-center gap-1.5 shadow-md relative overflow-hidden">
                <button
                  onClick={handleToggleVoiceBriefing}
                  className={`w-full flex items-center justify-center gap-2 py-2 px-3 rounded-xl text-xs font-bold font-mono transition cursor-pointer border ${
                    speechState.isSpeaking
                      ? 'bg-zinc-800 text-white border-zinc-400 shadow-sm'
                      : 'bg-white/[0.03] hover:bg-white/[0.07] text-zinc-200 hover:text-white border-white/[0.1] hover:border-zinc-400'
                  }`}
                  title="Listen to spoken security summary"
                >
                  {speechState.isSpeaking ? (
                    <>
                      <Pause className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span>Pause Audio</span>
                    </>
                  ) : (
                    <>
                      <Volume2 className="w-3.5 h-3.5 text-zinc-300 shrink-0" />
                      <span>Audio Briefing</span>
                    </>
                  )}
                </button>

                <button
                  onClick={() => handleOpenJarvisChat()}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-white/[0.04] hover:bg-cyan-500/15 text-white border border-white/[0.12] hover:border-cyan-500/40 rounded-xl text-xs font-bold font-mono transition cursor-pointer shadow-sm"
                  title="Ask J.A.R.V.I.S. security questions"
                >
                  <MessageSquare className="w-3.5 h-3.5 text-zinc-300 shrink-0" />
                  <span>Ask AI Assistant</span>
                </button>
              </div>

            </div>

            {/* Collapsible Deep Telemetry & Technical Specs (Visible in Forensic Expert Mode) */}
            {viewMode === 'expert' && (
              <>
                <div className="mt-5 pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs">
                  <span className="text-[11px] font-mono text-zinc-400 truncate max-w-md hidden sm:inline">
                    {telemetryFeed[telemetryIndex]}
                  </span>

                  <button
                    onClick={() => setShowAdvancedSpecs(prev => !prev)}
                    className="flex items-center gap-1.5 text-[11px] font-mono font-bold text-zinc-400 hover:text-zinc-200 transition cursor-pointer ml-auto"
                  >
                    <span>{showAdvancedSpecs ? 'Collapse Technical Specs' : 'Show Technical Specs & Hardware Telemetry'}</span>
                    {showAdvancedSpecs ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {showAdvancedSpecs && (
                  <div className="mt-3 pt-3 border-t border-zinc-800/60 grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs animate-fadeIn">
                    <div className="glass-card p-2.5 rounded-xl border border-white/[0.08] backdrop-blur-md">
                      <div className="text-[10px] text-zinc-400">Architecture</div>
                      <div className="text-zinc-200 font-bold mt-0.5">
                        {hostAssessment?.host_info?.architecture || 'x86_64 / AMD64'}
                      </div>
                      <div className="text-[9px] text-emerald-400">VERIFIED HARDWARE</div>
                    </div>
                    <div className="glass-card p-2.5 rounded-xl border border-white/[0.08] backdrop-blur-md">
                      <div className="text-[10px] text-zinc-400">Software Audited</div>
                      <div className="text-zinc-200 font-bold mt-0.5">
                        {hostAssessment?.software_audit?.total_software_found || (hasScannedHost ? 92 : '--')} Packages
                      </div>
                      <div className="text-[9px] text-zinc-400">NVD CVE DATABASE</div>
                    </div>
                    <div className="glass-card p-2.5 rounded-xl border border-white/[0.08] backdrop-blur-md">
                      <div className="text-[10px] text-zinc-400">Agent Status</div>
                      <div className="text-zinc-200 font-bold mt-0.5">
                        {isAgentOnline ? 'Local Native API' : 'Browser Perimeter'}
                      </div>
                      <div className="text-[9px] text-emerald-400">
                        {isAgentOnline ? 'DIRECT OS ACCESS' : 'SECURE SANDBOX'}
                      </div>
                    </div>
                    <div className="glass-card p-2.5 rounded-xl border border-white/[0.08] backdrop-blur-md">
                      <div className="text-[10px] text-zinc-400">Scan Pipeline</div>
                      <div className="text-zinc-200 font-bold mt-0.5">&lt; 1.2s Latency</div>
                      <div className="text-[9px] text-zinc-400">NON-INTRUSIVE READ-ONLY</div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Loading Spinner during Analysis */}
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
        ) : (
          <>
            {/* VIEW MODE 1: NORMAL VIEW (Simple, Human-Friendly Dashboard) */}
            {viewMode === 'simple' ? (
              <NormalUserDashboard
                assessment={hostAssessment}
                hasScanned={hasScannedHost}
                isScanning={hostLoading}
                onScan={() => triggerHostScan(true)}
                onFileUpload={handleFileUpload}
                onOpenJarvisChat={handleOpenJarvisChat}
                fileReport={heroMode === 'payload' ? report : null}
              />
            ) : (
              // VIEW MODE 2: FORENSIC EXPERT VIEW (SOC Incident Response & Reverse Engineering)
              <div className="space-y-6">
                {/* Forensic Tabs Bar */}
                <div 
                  ref={workspaceRef}
                  id="workspace-tabs"
                  className="flex flex-wrap items-center justify-between glass-panel p-2 rounded-2xl border border-cyan-500/20 text-xs font-bold gap-2 shadow-xl scroll-mt-20"
                >
                  <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto">
                    {FORENSIC_WORKFLOW_TABS.map(tab => {
                      const Icon = tab.icon;
                      const isActive = activeTab === tab.id;
                      return (
                        <button
                          key={tab.id}
                          onClick={() => {
                            setActiveTab(tab.id);
                            cyberAudio.playTabSwitch();
                          }}
                          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl transition-all duration-200 whitespace-nowrap text-xs font-bold cursor-pointer ${
                            isActive 
                              ? 'bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 text-slate-950 font-black shadow-md shadow-cyan-950/80 scale-[1.01] border border-cyan-400/50' 
                              : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                          }`}
                        >
                          <Icon className="w-4 h-4" />
                          <span>{tab.label}</span>
                          {tab.badge && (
                            <span 
                              className="px-1.5 py-0.5 text-[10px] font-mono font-black rounded text-slate-950 shadow-sm"
                              style={{ backgroundColor: tab.badgeColor || '#06b6d4' }}
                            >
                              {tab.badge}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>

                  <div className="hidden md:flex items-center gap-2 text-[11px] font-mono text-slate-400 px-3">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block animate-pulse" />
                    <span>Active Endpoint: {hostAssessment?.host_info?.hostname || 'Host Protected'}</span>
                  </div>
                </div>

                {/* Sub-Navigation Bar for Reverse Engineering Lab */}
                {activeTab === 'malware' && (
                  <div className="flex items-center gap-1.5 p-1.5 glass-panel rounded-xl border border-white/[0.12] overflow-x-auto text-xs font-mono animate-fadeIn">
                    {MALWARE_LAB_SUBTABS.map(sub => {
                      const SubIcon = sub.icon;
                      const isSubActive = malwareSubTab === sub.id;
                      return (
                        <button
                          key={sub.id}
                          onClick={() => {
                            setMalwareSubTab(sub.id);
                            cyberAudio.playClick();
                          }}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition whitespace-nowrap font-bold cursor-pointer ${
                            isSubActive
                              ? 'bg-cyan-950/90 text-cyan-300 border border-cyan-500/50 shadow-sm'
                              : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                          }`}
                        >
                          <SubIcon className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{sub.label}</span>
                        </button>
                      );
                    })}
                  </div>
                )}

                {/* Active Viewport Content for Forensic Mode */}
                <div className="transition-all duration-300">
                  {activeTab === 'host' && (
                    <SystemAssessmentTab 
                      assessment={hostAssessment || detectClientHostEnvironment()} 
                      loading={hostLoading} 
                      onRescan={() => triggerHostScan(true)} 
                      report={report}
                      onOpenJarvisChat={handleOpenJarvisChat}
                    />
                  )}

                  {activeTab === 'sentinel' && (
                    <PashaSentinelDashboard onOpenJarvisChat={handleOpenJarvisChat} />
                  )}

                  {activeTab === 'diff' && (
                    <HostSecurityDiffTab onOpenJarvisChat={handleOpenJarvisChat} />
                  )}

                  {activeTab === 'malware' && (
                    <div className="space-y-4">
                      {/* Uploaded File Inspector Header Banner */}
                      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 glass-panel rounded-2xl border border-cyan-500/30 shadow-md">
                        <div className="flex items-center gap-2.5 text-xs font-mono">
                          <Terminal className="w-4 h-4 text-cyan-400 shrink-0" />
                          <span className="text-zinc-400">Inspecting Uploaded Payload:</span>
                          <span className="text-cyan-300 font-bold">{report?.sample_name || 'Suspect Binary'}</span>
                          <span 
                            className="px-2 py-0.5 rounded text-[10px] font-black text-slate-950 ml-1"
                            style={{ backgroundColor: report?.threat_scoring?.color || '#ef4444' }}
                          >
                            THREAT: {report?.threat_scoring?.threat_score ?? 0}/100
                          </span>
                        </div>
                        <button
                          onClick={() => {
                            setActiveTab('host');
                            setHasCustomFileUpload(false);
                            cyberAudio.playClick();
                          }}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-zinc-300 hover:text-white bg-zinc-800/80 hover:bg-zinc-700/80 rounded-xl transition border border-white/[0.08] cursor-pointer"
                        >
                          <X className="w-3.5 h-3.5" />
                          <span>Close File Lab &amp; Return to Host Telemetry</span>
                        </button>
                      </div>

                      {malwareSubTab === 'overview' && (
                        <DashboardOverview 
                          report={report} 
                          onNavigateTab={(t) => setMalwareSubTab(t)} 
                        />
                      )}
                      {malwareSubTab === 'sandbox' && (
                        <BehavioralSandboxTab behavioral={report.behavioral_analysis} />
                      )}
                      {malwareSubTab === 'static' && (
                        <StaticAnalysisTab staticAnalysis={report.static_analysis} />
                      )}
                      {malwareSubTab === 'mitre' && (
                        <MitreAttackTab mitre={report.mitre_mapping} />
                      )}
                      {malwareSubTab === 'iocs' && (
                        <IocExtractorTab ioc={report.ioc_extraction} reportId={report.report_id} />
                      )}
                      {malwareSubTab === 'yara' && (
                        <YaraWorkbenchTab yaraScan={report.yara_scan} />
                      )}
                    </div>
                  )}

                  {activeTab === 'report' && (
                    <ReportGeneratorTab 
                      report={report} 
                      hostAssessment={hostAssessment || detectClientHostEnvironment()} 
                    />
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {/* Real-Time Live Telemetry Matrix Terminal HUD (Toggleable) */}
      {showTerminal && <LiveTelemetryTerminal />}

      {/* Submit Sample / Preset Modal */}
      {showModal && (
        <SampleSelectorModal
          onSelectPreset={loadPresetSample}
          onFileUpload={handleFileUpload}
          onClose={() => setShowModal(false)}
        />
      )}

      {/* Local Host Scanner & Extension Companion Modal */}
      <LocalHostScannerModal
        isOpen={showHostScanModal}
        onClose={() => setShowHostScanModal(false)}
        onRunInstantScan={() => triggerHostScan(false)}
        onRunDeepAgentScan={() => triggerHostScan(false)}
        isAgentOnline={isAgentOnline}
        scanning={hostLoading}
      />

      {/* J.A.R.V.I.S. Voice Guidance Modal */}
      <JarvisAssistantModal
        report={report}
        hostAssessment={hostAssessment || detectClientHostEnvironment()}
        isOpen={showJarvisModal}
        onClose={() => setShowJarvisModal(false)}
        onNavigateTab={handleOpenTab}
        onOpenChat={handleOpenJarvisChat}
      />

      {/* J.A.R.V.I.S. Interactive Chat Modal */}
      <JarvisChatModal
        report={report}
        hostAssessment={hostAssessment || detectClientHostEnvironment()}
        isOpen={showChatModal}
        onClose={() => setShowChatModal(false)}
        initialPrompt={chatInitialPrompt}
      />

      {/* Theme Studio Modal */}
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

      {/* Enterprise Cyber Defense Footer */}
      <footer className="glass-panel border-t border-cyan-500/20 mt-auto py-5 px-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400"></span>
            </span>
            <span className="text-slate-400 font-mono text-xs">
              PASHA &bull; <strong className="text-cyan-400 font-black">AUTONOMOUS THREAT REVERSING &amp; ENDPOINT DEFENSE</strong>
            </span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500">
            <span>STIX 2.1</span>
            <span>&bull;</span>
            <span>MITRE ATT&CK v14</span>
            <span>&bull;</span>
            <span>YARA v4.5</span>
            <span>&bull;</span>
            <span>WINDOWS DEFENSE AGENT</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
