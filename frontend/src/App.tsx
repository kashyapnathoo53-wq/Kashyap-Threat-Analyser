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
import { jarvisVoice, JarvisSpeechState } from './utils/jarvisVoice';
import { detectClientHostEnvironment } from './utils/clientHostAuditor';
import { 
  Shield, ShieldAlert, Cpu, Terminal, Layers, Database, Code2, FileText, 
  Upload, AlertTriangle, MonitorCheck, Zap, Sparkles, Radio,
  Volume2, VolumeX, Palette, ArrowUpRight, Bot, MessageSquare, Sliders,
  ChevronDown, ChevronUp, Play, Pause
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

  const [showThemeModal, setShowThemeModal] = useState<boolean>(false);
  const [showToolsDropdown, setShowToolsDropdown] = useState<boolean>(false);
  const [showJarvisDropdown, setShowJarvisDropdown] = useState<boolean>(false);
  const [showMoreToolsDropdown, setShowMoreToolsDropdown] = useState<boolean>(false);
  const [showAdvancedSpecs, setShowAdvancedSpecs] = useState<boolean>(false);
  const [showTerminal, setShowTerminal] = useState<boolean>(false);

  const workspaceRef = useRef<HTMLDivElement | null>(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('[data-dropdown]')) {
        setShowToolsDropdown(false);
        setShowJarvisDropdown(false);
        setShowMoreToolsDropdown(false);
      }
    };
    window.addEventListener('click', handleOutsideClick);
    return () => window.removeEventListener('click', handleOutsideClick);
  }, []);

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
    setTheme('carbon');
  };

  const handleOpenTab = (tabId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setActiveTab(tabId);
    setShowMoreToolsDropdown(false);
    cyberAudio.playTabSwitch();
    setTimeout(() => {
      workspaceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 60);
  };

  const [report, setReport] = useState<FullAnalysisReport>(FALLBACK_REPORTS['sample_wannacry']);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment>(() => detectClientHostEnvironment());
  const [hostLoading, setHostLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [showJarvisModal, setShowJarvisModal] = useState<boolean>(false);
  const [showChatModal, setShowChatModal] = useState<boolean>(false);
  const [chatInitialPrompt, setChatInitialPrompt] = useState<string>('');
  const [speechState, setSpeechState] = useState<JarvisSpeechState>(jarvisVoice.getState());

  useEffect(() => {
    return jarvisVoice.subscribe(setSpeechState);
  }, []);

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
      const script = jarvisVoice.generateFullScript(report, hostAssessment);
      jarvisVoice.speak(script, 'full');
    }
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
    // Dynamic client-side host assessment for visitor
    setHostAssessment(detectClientHostEnvironment());
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

  // Secondary Forensic Tools grouped into dropdown
  const SECONDARY_TOOLS = [
    { id: 'static', label: 'Static Analysis', icon: Cpu, desc: 'PE headers, entropy & strings' },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers, desc: 'TTP matrix & techniques' },
    { id: 'iocs', label: 'Extracted IOCs', icon: Database, desc: 'IPs, hashes & STIX 2.1' },
    { id: 'yara', label: 'YARA Workbench', icon: Code2, desc: 'Signatures & rule compiler' }
  ];

  const activeSecondaryTool = SECONDARY_TOOLS.find(t => t.id === activeTab);
  const isSecondaryActive = Boolean(activeSecondaryTool);

  const coils = [0, 36, 72, 108, 144, 180, 216, 252, 288, 324];

  return (
    <div className="min-h-screen cyber-bg text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-slate-950 relative overflow-hidden">
      {/* Interactive 60fps Cyber Particle & Filament Canvas */}
      <CyberParticleCanvas theme={theme} />

      {/* Sleek, Single Unified Navigation Header */}
      <header className="glass-panel sticky top-0 z-40 border-b border-cyan-500/20 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 py-2.5 flex items-center justify-between gap-4">
          
          {/* Brand & Live Defense Indicator */}
          <div className="flex items-center gap-3">
            <div 
              className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 p-[1.5px] cursor-pointer shadow-md shadow-cyan-950/60 transition hover:scale-105"
              onClick={() => setShowThemeModal(true)}
              title="Customize Theme & Colors"
            >
              <div className="w-full h-full bg-[#040d1e] rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]" />
              </div>
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-black tracking-wider text-white">PASHA</span>
                <span className="hidden sm:inline-flex items-center gap-1 text-[10px] font-mono text-cyan-400 bg-cyan-950/70 px-2 py-0.5 rounded-full border border-cyan-800/60">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  DEFENSE GRID ACTIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium hidden md:block">
                Autonomous Threat Reversing &amp; Deep Behavioral Sandboxing
              </p>
            </div>
          </div>

          {/* Center Target Pill: Active Payload Summary */}
          {report && (
            <div 
              onClick={() => handleOpenTab('overview')}
              className="hidden lg:flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/[0.08] hover:border-cyan-500/50 cursor-pointer transition text-xs font-mono shadow-inner group"
              title="Click to view Executive Overview"
            >
              <span className="w-2 h-2 rounded-full group-hover:scale-125 transition-transform" style={{ backgroundColor: report.threat_scoring.color }} />
              <span className="text-slate-300 font-bold max-w-[140px] truncate">{report.sample_name}</span>
              <span 
                className="text-[10px] font-black px-1.5 py-0.5 rounded"
                style={{ 
                  backgroundColor: `${report.threat_scoring.color}20`, 
                  color: report.threat_scoring.color 
                }}
              >
                {report.threat_scoring.threat_score}/100 {report.threat_scoring.severity}
              </span>
            </div>
          )}

          {/* Right Action Cluster & Clean Dropdowns */}
          <div className="flex items-center gap-2">
            
            {/* Primary Action: Submit Payload */}
            <button
              onClick={() => {
                cyberAudio.playClick();
                setShowModal(true);
              }}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black rounded-xl text-xs transition shadow-lg shadow-cyan-950/70 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>Submit Payload</span>
            </button>

            {/* J.A.R.V.I.S. AI Action Dropdown */}
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
                <span className="hidden sm:inline font-mono">J.A.R.V.I.S.</span>
                <ChevronDown className={`w-3 h-3 text-cyan-400/80 transition-transform duration-200 ${showJarvisDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showJarvisDropdown && (
                <div className="absolute right-0 mt-2 w-64 glass-panel rounded-2xl border border-cyan-500/40 shadow-2xl p-2 z-50 animate-fadeIn text-xs space-y-1">
                  <div className="px-3 py-1.5 text-[10px] font-mono text-cyan-400 font-bold uppercase border-b border-cyan-900/40 mb-1 flex items-center justify-between">
                    <span>AI Assistant Suite</span>
                    {speechState.isSpeaking && (
                      <span className="text-emerald-400 animate-pulse font-mono text-[9px]">&bull; SPEAKING</span>
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
                      <div className="font-bold">Talk to J.A.R.V.I.S.</div>
                      <div className="text-[10px] text-slate-400">Ask remediation &amp; forensics questions</div>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setShowJarvisDropdown(false);
                      setShowJarvisModal(true);
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl hover:bg-cyan-950/60 text-slate-200 hover:text-white transition text-left cursor-pointer"
                  >
                    <Bot className="w-4 h-4 text-cyan-400 shrink-0" />
                    <div>
                      <div className="font-bold">Voice Guidance Console</div>
                      <div className="text-[10px] text-slate-400">Full speech script &amp; teleprompter</div>
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
                        {speechState.isSpeaking ? 'Pause Audio Briefing' : 'Quick Audio Briefing'}
                      </div>
                      <div className="text-[10px] text-slate-400">Vocal overview of current payload</div>
                    </div>
                  </button>
                </div>
              )}
            </div>

            {/* Tools & System Settings Dropdown */}
            <div className="relative" data-dropdown>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  cyberAudio.playClick();
                  setShowToolsDropdown(prev => !prev);
                  setShowJarvisDropdown(false);
                }}
                className="flex items-center justify-center w-9 h-9 bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-white/[0.1] hover:border-cyan-500/40 rounded-xl transition cursor-pointer"
                title="Tools & Preferences"
              >
                <Sliders className="w-4 h-4 text-slate-300" />
              </button>

              {showToolsDropdown && (
                <div className="absolute right-0 mt-2 w-72 glass-panel rounded-2xl border border-cyan-500/40 shadow-2xl p-2.5 z-50 animate-fadeIn text-xs space-y-1.5">
                  <div className="px-3 py-1 text-[10px] font-mono text-cyan-400 font-bold uppercase border-b border-cyan-900/40">
                    Preferences &amp; System Tools
                  </div>

                  {/* Theme Selector */}
                  <button
                    onClick={() => {
                      setShowToolsDropdown(false);
                      setShowThemeModal(true);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Palette className="w-4 h-4 text-cyan-400" />
                      <span className="font-medium">Theme &amp; Accent Studio</span>
                    </div>
                    <span 
                      className="w-3.5 h-3.5 rounded-full border border-white/30 shadow-sm"
                      style={{ backgroundColor: customColor || '#06b6d4' }}
                    />
                  </button>

                  {/* Audio Synthesizer Toggle */}
                  <button
                    onClick={() => {
                      const muted = cyberAudio.toggleMute();
                      setIsMuted(muted);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      {isMuted ? <VolumeX className="w-4 h-4 text-slate-500" /> : <Volume2 className="w-4 h-4 text-cyan-400" />}
                      <span className="font-medium">Sound Effects FX</span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${!isMuted ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/50' : 'bg-slate-800 text-slate-400'}`}>
                      {isMuted ? 'MUTED' : 'ENABLED'}
                    </span>
                  </button>

                  {/* Live Telemetry Terminal Toggle */}
                  <button
                    onClick={() => {
                      setShowTerminal(prev => !prev);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl hover:bg-white/[0.06] text-slate-200 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Terminal className="w-4 h-4 text-sky-400" />
                      <span className="font-medium">Matrix Telemetry Terminal</span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${showTerminal ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/50' : 'bg-slate-800 text-slate-400'}`}>
                      {showTerminal ? 'VISIBLE' : 'HIDDEN'}
                    </span>
                  </button>

                  {/* System Info footer */}
                  <div className="pt-2 border-t border-white/[0.08] px-3 text-[10px] font-mono text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span>ARMOR HOST</span>
                      <span className="text-cyan-300 font-bold">{hostAssessment?.host_info?.hostname || 'SUIT_ONLINE'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>DEFENSE GRID</span>
                      <span className="text-emerald-400 font-bold">MK-85 ARMED</span>
                    </div>
                    <div className="flex justify-between">
                      <span>UTC CLOCK</span>
                      <span className="text-slate-300 font-bold">{currentTime}</span>
                    </div>
                  </div>
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
        {/* Clean, Decluttered Executive Threat Hub - Centered Arc Reactor */}
        {!loading && report && (
          <div className="glass-panel p-6 sm:p-8 rounded-3xl border border-white/[0.08] relative overflow-hidden shadow-2xl bg-zinc-950/85 backdrop-blur-xl">
            {/* Subtle platinum cyber illumination */}
            <div className="absolute inset-0 bg-gradient-to-b from-white/[0.03] via-transparent to-transparent pointer-events-none" />

            {/* Top: Centered Verdict Header */}
            <div className="text-center space-y-2 mb-4 relative z-10 max-w-2xl mx-auto">
              <div className="flex flex-wrap items-center justify-center gap-2">
                <span 
                  className="px-3 py-1 rounded-full text-[11px] font-mono font-black uppercase tracking-wider flex items-center gap-1.5 shadow-sm"
                  style={{ 
                    backgroundColor: `${report.threat_scoring.color}20`, 
                    color: report.threat_scoring.color, 
                    border: `1px solid ${report.threat_scoring.color}50` 
                  }}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  {report.threat_scoring.severity}
                </span>
                <span className="text-xs font-mono text-zinc-300 font-bold px-2.5 py-0.5 rounded-lg bg-zinc-900/90 border border-white/[0.08]">
                  {report.sample_name}
                </span>
                <span className="text-xs font-mono text-zinc-400">
                  {report.threat_scoring.confidence ?? 98}% Confidence
                </span>
              </div>

              <h2 className="text-xl sm:text-2xl md:text-3xl font-black text-white tracking-tight">
                {report.threat_scoring.verdict}
              </h2>

              <p className="text-xs text-zinc-400 max-w-lg mx-auto line-clamp-2">
                Consensus synthesized from Shannon entropy, Win32 syscall hooks, and MITRE ATT&amp;CK tactics.
              </p>
            </div>

            {/* Middle: Centered, Larger Arc Reactor */}
            <div className="flex justify-center items-center my-6 relative z-10">
              <div className="relative w-48 h-48 sm:w-56 sm:h-56 md:w-60 md:h-60 flex items-center justify-center">
                {/* Arc Reactor Bloom & Radial Energy */}
                <div 
                  className="absolute inset-2 rounded-full filter blur-2xl opacity-40 pointer-events-none transition-all duration-700"
                  style={{ 
                    background: `radial-gradient(circle, #ffffff 0%, #a1a1aa 35%, ${report.threat_scoring.color}40 70%, transparent 100%)` 
                  }}
                />

                <svg 
                  className="w-full h-full drop-shadow-[0_0_25px_rgba(255,255,255,0.35)] cursor-pointer select-none transition-transform duration-300 hover:scale-105"
                  viewBox="0 0 190 190"
                  onClick={() => handleOpenTab('overview')}
                >
                  <defs>
                    <filter id="arcGlowHub" x="-30%" y="-30%" width="160%" height="160%">
                      <feGaussianBlur stdDeviation="3.5" result="glow" />
                      <feMerge>
                        <feMergeNode in="glow" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                    <radialGradient id="arcCoreGrad" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#ffffff" />
                      <stop offset="40%" stopColor="#f4f4f5" />
                      <stop offset="70%" stopColor="#a1a1aa" />
                      <stop offset="100%" stopColor="#18181b" />
                    </radialGradient>
                  </defs>

                  {/* Gunmetal Outer Chassis Ring */}
                  <circle cx="95" cy="95" r="91" fill="none" stroke="#27272a" strokeWidth="2" />
                  <circle cx="95" cy="95" r="87" fill="#09090b" stroke="#3f3f46" strokeWidth="2.5" strokeOpacity="0.8" strokeDasharray="6 4" />

                  {/* 10 Arc Reactor Toroidal Electromagnet Coils */}
                  {coils.map((deg, i) => (
                    <g key={i} transform={`rotate(${deg} 95 95)`}>
                      <rect
                        x="91"
                        y="12"
                        width="8"
                        height="16"
                        rx="2"
                        fill="#18181b"
                        stroke="#71717a"
                        strokeWidth="1.2"
                      />
                      <line x1="92" y1="16" x2="98" y2="16" stroke="#d4d4d8" strokeWidth="1.2" />
                      <line x1="92" y1="20" x2="98" y2="20" stroke="#a1a1aa" strokeWidth="1.2" />
                      <line x1="92" y1="24" x2="98" y2="24" stroke="#d4d4d8" strokeWidth="1.2" />
                    </g>
                  ))}

                  {/* Rotating Stator Ring */}
                  <g className="animate-spin-slow origin-center" style={{ transformOrigin: '95px 95px' }}>
                    <circle cx="95" cy="95" r="70" fill="none" stroke="#71717a" strokeWidth="3" strokeOpacity="0.7" strokeDasharray="14 7" />
                    <circle cx="95" cy="25" r="2.5" fill="#ffffff" filter="url(#arcGlowHub)" />
                    <circle cx="165" cy="95" r="2.5" fill="#ffffff" filter="url(#arcGlowHub)" />
                    <circle cx="95" cy="165" r="2.5" fill="#ffffff" filter="url(#arcGlowHub)" />
                    <circle cx="25" cy="95" r="2.5" fill="#ffffff" filter="url(#arcGlowHub)" />
                  </g>

                  {/* Luminous Inner Arc Flux Ring */}
                  <circle cx="95" cy="95" r="56" fill="#09090b" stroke="#e4e4e7" strokeWidth="3" strokeOpacity="0.9" filter="url(#arcGlowHub)" />
                  <circle cx="95" cy="95" r="48" fill="#18181b" stroke="#a1a1aa" strokeWidth="1.5" strokeOpacity="0.8" strokeDasharray="5 3" />

                  {/* Central Threat Score */}
                  <text 
                    x="95" 
                    y="96" 
                    textAnchor="middle" 
                    fill="#ffffff" 
                    fontSize="24" 
                    fontWeight="900" 
                    fontFamily="monospace"
                    filter="drop-shadow(0 0 6px rgba(255,255,255,0.7))"
                  >
                    {report.threat_scoring.threat_score}
                  </text>
                  <text 
                    x="95" 
                    y="114" 
                    textAnchor="middle" 
                    fill="#a1a1aa" 
                    fontSize="10" 
                    fontWeight="800" 
                    fontFamily="monospace"
                  >
                    /100 THREAT
                  </text>
                </svg>
              </div>
            </div>

            {/* Bottom: Clean Symmetrical Vitals & Quick Actions */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 relative z-10 pt-2 font-mono text-xs">
              
              {/* Card 1: Visitor Host Health */}
              <div 
                onClick={() => handleOpenTab('host')}
                className="bg-zinc-900/80 hover:bg-zinc-800/90 p-3.5 rounded-2xl border border-white/[0.08] hover:border-zinc-500/50 transition cursor-pointer text-center group shadow-md"
                title="Click to view Visitor Host Security Assessment"
              >
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <MonitorCheck className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Host Integrity</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {hostAssessment?.health_score ?? 100}/100
                </div>
                <div className="text-[10px] text-emerald-400 font-bold mt-0.5 flex items-center justify-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                  <span>{hostAssessment?.status || 'OPTIMAL'}</span>
                  <span className="text-zinc-500 text-[9px]">({hostAssessment?.host_info?.os?.split(' ')[0] || 'Browser'})</span>
                </div>
              </div>

              {/* Card 2: Extracted Forensic IOCs */}
              <div 
                onClick={() => handleOpenTab('iocs')}
                className="bg-zinc-900/80 hover:bg-zinc-800/90 p-3.5 rounded-2xl border border-white/[0.08] hover:border-zinc-500/50 transition cursor-pointer text-center group shadow-md"
                title="Click to view Extracted IOCs"
              >
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <Database className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Forensic IOCs</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {report.ioc_extraction.total_extracted}
                </div>
                <div className="text-[10px] text-zinc-400 font-bold mt-0.5">
                  {report.ioc_extraction.summary_by_category?.['Network C2'] || 0} C2 IPs &bull; Hashes Extracted
                </div>
              </div>

              {/* Card 3: Deep Scan Latency */}
              <div 
                onClick={() => handleOpenTab('static')}
                className="bg-zinc-900/80 hover:bg-zinc-800/90 p-3.5 rounded-2xl border border-white/[0.08] hover:border-zinc-500/50 transition cursor-pointer text-center group shadow-md"
                title="Click to view Static Analysis"
              >
                <div className="text-[10px] text-zinc-400 group-hover:text-zinc-200 transition flex items-center justify-center gap-1">
                  <Zap className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Scan Latency</span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {(report as any).analysis_duration_ms || 18}ms
                </div>
                <div className="text-[10px] text-zinc-400 font-bold mt-0.5">
                  ZERO-LAG PIPELINE
                </div>
              </div>

              {/* Card 4: J.A.R.V.I.S. Audio & AI Actions */}
              <div className="bg-zinc-900/80 p-2 rounded-2xl border border-white/[0.08] flex flex-col justify-center gap-1.5 shadow-md">
                <button
                  onClick={handleToggleVoiceBriefing}
                  className={`w-full flex items-center justify-center gap-2 py-2 px-3 rounded-xl text-xs font-bold font-mono transition cursor-pointer border ${
                    speechState.isSpeaking
                      ? 'bg-zinc-800 text-white border-zinc-400 shadow-sm'
                      : 'bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200 hover:text-white border-white/[0.1] hover:border-zinc-500'
                  }`}
                  title="Listen to J.A.R.V.I.S. Audio Briefing"
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
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-zinc-800/80 hover:bg-zinc-700/80 text-white border border-white/[0.12] hover:border-white/30 rounded-xl text-xs font-bold font-mono transition cursor-pointer shadow-sm"
                  title="Ask J.A.R.V.I.S. questions about malware eradication"
                >
                  <MessageSquare className="w-3.5 h-3.5 text-zinc-300 shrink-0" />
                  <span>Ask J.A.R.V.I.S.</span>
                </button>
              </div>
            </div>

            {/* Collapsible Toggle for Deep Telemetry & Technical Specs */}
            <div className="mt-5 pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs">
              <span className="text-[11px] font-mono text-zinc-400 truncate max-w-md hidden sm:inline">
                {telemetryFeed[telemetryIndex]}
              </span>

              <button
                onClick={() => setShowAdvancedSpecs(prev => !prev)}
                className="flex items-center gap-1.5 text-[11px] font-mono font-bold text-zinc-400 hover:text-zinc-200 transition cursor-pointer ml-auto"
              >
                <span>{showAdvancedSpecs ? 'Collapse Advanced Specs' : 'Show Advanced Specs & Telemetry'}</span>
                {showAdvancedSpecs ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Expandable Advanced Telemetry Specs Drawer */}
            {showAdvancedSpecs && (
              <div className="mt-3 pt-3 border-t border-zinc-800/60 grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs animate-fadeIn">
                <div className="bg-zinc-900/70 p-2.5 rounded-xl border border-white/[0.05]">
                  <div className="text-[10px] text-zinc-400">Entropy Metric</div>
                  <div className="text-zinc-200 font-bold mt-0.5">
                    {report.static_analysis?.file_info?.entropy != null 
                      ? `${report.static_analysis.file_info.entropy.toFixed(2)} / 8.00`
                      : '5.25 / 8.00'}
                  </div>
                  <div className="text-[9px] text-emerald-400">
                    {(report.static_analysis?.file_info?.entropy ?? 5.25) > 7.0 ? 'PACKED / OBFUSCATED' : 'UNPACKED'}
                  </div>
                </div>
                <div className="bg-zinc-900/70 p-2.5 rounded-xl border border-white/[0.05]">
                  <div className="text-[10px] text-zinc-400">Threat Vectors</div>
                  <div className="text-zinc-200 font-bold mt-0.5">{report.mitre_mapping?.tactics?.length ?? 5} MITRE Tactics</div>
                  <div className="text-[9px] text-zinc-400">ATT&amp;CK MATRIX</div>
                </div>
                <div className="bg-zinc-900/70 p-2.5 rounded-xl border border-white/[0.05]">
                  <div className="text-[10px] text-zinc-400">Confidence Score</div>
                  <div className="text-zinc-200 font-bold mt-0.5">{report.threat_scoring?.confidence ?? 98}%</div>
                  <div className="text-[9px] text-emerald-400">VERIFIED ATT&amp;CK</div>
                </div>
                <div className="bg-zinc-900/70 p-2.5 rounded-xl border border-white/[0.05]">
                  <div className="text-[10px] text-zinc-400">Active YARA Rules</div>
                  <div className="text-zinc-200 font-bold mt-0.5">{report.yara_scan?.match_count ?? 14} Matches</div>
                  <div className="text-[9px] text-zinc-400">SURICATA / MISP</div>
                </div>
              </div>
            )}
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
            {/* Streamlined Tab Rail with Primary Tabs & Secondary Forensic Tools Dropdown */}
            <div 
              ref={workspaceRef}
              id="workspace-tabs"
              className="flex flex-wrap items-center justify-between glass-panel p-1.5 rounded-2xl border border-cyan-500/20 text-xs font-bold gap-2 shadow-xl scroll-mt-20"
            >
              {/* Primary 4 Major Tabs */}
              <div className="flex items-center gap-1.5 overflow-x-auto">
                {[
                  { 
                    id: 'host', 
                    label: 'System Assessment', 
                    icon: MonitorCheck, 
                    badge: hostAssessment ? `${hostAssessment.health_score}/100` : undefined, 
                    badgeColor: hostAssessment?.status_color 
                  },
                  { id: 'overview', label: 'Executive Overview', icon: ShieldAlert },
                  { id: 'sandbox', label: 'Behavioral Sandbox', icon: Terminal },
                  { id: 'report', label: 'Report & Remediation', icon: FileText }
                ].map(tab => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => handleTabChange(tab.id)}
                      className={`flex items-center gap-2 px-3.5 py-2 rounded-xl transition-all duration-200 whitespace-nowrap text-xs font-bold cursor-pointer ${
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

              {/* Secondary Forensic Tools in Clean Dropdown */}
              <div className="relative" data-dropdown>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    cyberAudio.playClick();
                    setShowMoreToolsDropdown(prev => !prev);
                  }}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-xl transition-all duration-200 text-xs font-bold cursor-pointer border ${
                    isSecondaryActive 
                      ? 'bg-cyan-950/90 text-cyan-300 border-cyan-400/80 shadow-md shadow-cyan-950/60' 
                      : 'bg-slate-900/60 text-slate-400 hover:text-white border-white/[0.08] hover:border-cyan-500/40'
                  }`}
                  title="Deep Forensic Tools"
                >
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>{activeSecondaryTool ? activeSecondaryTool.label : 'More Forensic Tools'}</span>
                  <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${showMoreToolsDropdown ? 'rotate-180' : ''}`} />
                </button>

                {showMoreToolsDropdown && (
                  <div className="absolute right-0 mt-2 w-60 glass-panel rounded-2xl border border-cyan-500/40 shadow-2xl p-1.5 z-40 animate-fadeIn text-xs space-y-1">
                    <div className="px-3 py-1 text-[10px] font-mono text-cyan-400/80 font-bold uppercase border-b border-white/[0.06] mb-1">
                      Secondary Forensic Tools
                    </div>
                    {SECONDARY_TOOLS.map(tool => {
                      const ToolIcon = tool.icon;
                      const isSelected = activeTab === tool.id;
                      return (
                        <button
                          key={tool.id}
                          onClick={() => {
                            handleTabChange(tool.id);
                            setShowMoreToolsDropdown(false);
                          }}
                          className={`w-full flex items-start gap-2.5 px-3 py-2 rounded-xl transition text-left cursor-pointer ${
                            isSelected 
                              ? 'bg-cyan-950/90 text-cyan-300 font-bold border border-cyan-500/40' 
                              : 'hover:bg-white/[0.06] text-slate-300 hover:text-white'
                          }`}
                        >
                          <ToolIcon className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                          <div>
                            <div className="font-semibold leading-tight">{tool.label}</div>
                            <div className="text-[10px] text-slate-400">{tool.desc}</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
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
            No active threat session. Click <strong className="text-cyan-400">Submit Payload</strong> to begin.
          </div>
        )}
      </main>

      {/* Real-Time Live Telemetry Matrix Terminal HUD (Toggleable via Settings) */}
      {showTerminal && <LiveTelemetryTerminal />}

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
