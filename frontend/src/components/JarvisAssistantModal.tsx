import React, { useState, useEffect, useRef } from 'react';
import { FullAnalysisReport, HostAssessment } from '../types';
import { jarvisVoice, JarvisSpeechState } from '../utils/jarvisVoice';
import { cyberAudio } from '../utils/cyberAudio';
import { 
  X, Volume2, VolumeX, Play, Pause, Square, RotateCcw, 
  ShieldAlert, MonitorCheck, ShieldCheck, Sparkles, Radio, 
  Copy, Check, Bot, AlertTriangle, ChevronRight, Zap, Flame,
  Layers, Terminal, ArrowUpRight
} from 'lucide-react';

interface JarvisAssistantModalProps {
  report: FullAnalysisReport | null;
  hostAssessment: HostAssessment | null;
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab?: (tabId: string) => void;
}

type Topic = 'full' | 'file' | 'system' | 'solution';

export const JarvisAssistantModal: React.FC<JarvisAssistantModalProps> = ({
  report,
  hostAssessment,
  isOpen,
  onClose,
  onNavigateTab
}) => {
  const [activeTopic, setActiveTopic] = useState<Topic>('full');
  const [speechState, setSpeechState] = useState<JarvisSpeechState>(jarvisVoice.getState());
  const [speed, setSpeed] = useState<number>(1.0);
  const [copied, setCopied] = useState<boolean>(false);
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoiceName, setSelectedVoiceName] = useState<string>('');
  const teleprompterRef = useRef<HTMLDivElement | null>(null);

  // Subscribe to speech updates
  useEffect(() => {
    const unsub = jarvisVoice.subscribe(setSpeechState);
    const availVoices = jarvisVoice.getAvailableVoices();
    setVoices(availVoices);
    const curr = jarvisVoice.getSelectedVoice();
    if (curr) setSelectedVoiceName(curr.name);
    return unsub;
  }, []);

  // Update script whenever topic, report, or host changes
  const getScriptForTopic = (t: Topic): string => {
    switch (t) {
      case 'file':
        return jarvisVoice.generateFileScript(report);
      case 'system':
        return jarvisVoice.generateSystemScript(hostAssessment);
      case 'solution':
        return jarvisVoice.generateSolutionScript(report, hostAssessment);
      case 'full':
      default:
        return jarvisVoice.generateFullScript(report, hostAssessment);
    }
  };

  const currentScript = getScriptForTopic(activeTopic);

  // Auto-scroll teleprompter as word index changes
  useEffect(() => {
    if (teleprompterRef.current && speechState.currentCharIndex > 0) {
      const activeEl = teleprompterRef.current.querySelector('[data-active="true"]');
      if (activeEl) {
        activeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [speechState.currentCharIndex]);

  if (!isOpen) return null;

  const handlePlay = (topicToPlay: Topic = activeTopic) => {
    cyberAudio.playClick();
    setActiveTopic(topicToPlay);
    const text = getScriptForTopic(topicToPlay);
    jarvisVoice.setRate(speed);
    jarvisVoice.speak(text, topicToPlay);
  };

  const handlePauseResume = () => {
    cyberAudio.playClick();
    if (speechState.isPaused) {
      jarvisVoice.resume();
    } else if (speechState.isSpeaking) {
      jarvisVoice.pause();
    } else {
      handlePlay(activeTopic);
    }
  };

  const handleStop = () => {
    cyberAudio.playClick();
    jarvisVoice.stop();
  };

  const handleCopyScript = () => {
    cyberAudio.playClick();
    navigator.clipboard.writeText(currentScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSpeedChange = (newSpeed: number) => {
    cyberAudio.playClick();
    setSpeed(newSpeed);
    jarvisVoice.setRate(newSpeed);
    if (speechState.isSpeaking && !speechState.isPaused) {
      // Re-trigger with new rate from current position or full
      jarvisVoice.speak(currentScript, activeTopic);
    }
  };

  const handleVoiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const name = e.target.value;
    setSelectedVoiceName(name);
    jarvisVoice.setVoiceByName(name);
    if (speechState.isSpeaking) {
      jarvisVoice.speak(currentScript, activeTopic);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-fadeIn">
      <div 
        className="relative w-full max-w-4xl max-h-[92vh] flex flex-col rounded-3xl overflow-hidden border border-amber-500/40 shadow-2xl shadow-red-950/80 bg-[#0c0305]"
        style={{
          backgroundImage: 'radial-gradient(ellipse at 50% 0%, rgba(220, 38, 38, 0.22) 0%, rgba(11, 3, 4, 0.98) 75%)'
        }}
      >
        {/* Top Header Bar */}
        <div className="px-6 py-4 border-b border-amber-900/40 flex items-center justify-between bg-[#150508]/80">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 via-amber-600 to-yellow-500 flex items-center justify-center text-slate-950 font-black shadow-lg shadow-red-950/60">
                <Bot className="w-5 h-5 stroke-[2.5]" />
              </div>
              <span className="absolute -bottom-1 -right-1 flex h-3 w-3">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${speechState.isSpeaking && !speechState.isPaused ? 'bg-cyan-400' : 'bg-amber-400'}`} />
                <span className={`relative inline-flex rounded-full h-3 w-3 ${speechState.isSpeaking && !speechState.isPaused ? 'bg-cyan-400' : 'bg-amber-500'}`} />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-amber-200 via-yellow-400 to-red-400">
                  J.A.R.V.I.S. TACTICAL AI AUDIO GUIDE
                </h3>
                <span className="px-2 py-0.5 text-[10px] font-mono font-black uppercase rounded-full bg-amber-950/90 text-amber-300 border border-amber-500/40">
                  MARK-85 ASSISTANT
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Real-time vocalized diagnosis of payload forensics, local host vulnerabilities &amp; tactical countermeasures
              </p>
            </div>
          </div>

          <button
            onClick={() => {
              cyberAudio.playClick();
              jarvisVoice.stop();
              onClose();
            }}
            className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900/70 border border-white/10 hover:border-amber-500/50 transition cursor-pointer"
            title="Close Assistant"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6">
          {/* Central Interactive Voice Hologram & Controller */}
          <div className="glass-card rounded-2xl p-5 border border-amber-500/30 bg-[#160609]/70 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-72 h-72 bg-gradient-to-bl from-amber-500/10 via-red-600/10 to-transparent pointer-events-none rounded-full blur-2xl" />

            <div className="flex flex-col md:flex-row items-center justify-between gap-6 relative z-10">
              {/* Voice Orb / Frequency Ring */}
              <div className="flex items-center gap-4">
                <div className="relative w-20 h-20 flex items-center justify-center">
                  {/* Rotating Outer Gyro Ring */}
                  <div 
                    className={`absolute inset-0 rounded-full border border-dashed border-amber-400/50 ${
                      speechState.isSpeaking && !speechState.isPaused ? 'animate-spin' : ''
                    }`}
                    style={{ animationDuration: '8s' }}
                  />
                  {/* Pulsing Arc Ring */}
                  <div 
                    className={`absolute inset-2 rounded-full border-2 border-cyan-400/60 transition-transform duration-300 ${
                      speechState.isSpeaking && !speechState.isPaused ? 'animate-ping opacity-60' : 'opacity-30'
                    }`}
                  />
                  {/* Core Jarvis Orb */}
                  <div className="w-12 h-12 rounded-full bg-gradient-to-tr from-red-600 via-amber-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-cyan-950/80 text-slate-950">
                    <Radio className={`w-6 h-6 stroke-[2.5] ${speechState.isSpeaking && !speechState.isPaused ? 'animate-pulse text-white' : 'text-slate-950'}`} />
                  </div>
                </div>

                {/* Status & Active Voice Indicator */}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400">
                      {speechState.isSpeaking 
                        ? (speechState.isPaused ? 'Vocal Engine: Paused' : 'J.A.R.V.I.S. Speaking...') 
                        : 'Vocal Engine: Standing By'}
                    </span>
                    {speechState.isSpeaking && !speechState.isPaused && (
                      <span className="flex items-center gap-0.5">
                        <span className="w-1 h-3 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1 h-5 bg-amber-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1 h-4 bg-red-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                        <span className="w-1 h-6 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '450ms' }} />
                      </span>
                    )}
                  </div>
                  <div className="text-sm font-black text-slate-200 mt-0.5">
                    {activeTopic === 'full' && 'Comprehensive Malicious Threat & Remediation Briefing'}
                    {activeTopic === 'file' && 'Malicious File & Binary Forensic Breakdown'}
                    {activeTopic === 'system' && 'Host System Endpoint Anomaly Audit'}
                    {activeTopic === 'solution' && 'Recommended Solution & Mitigation Protocols'}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center gap-3">
                    <span>Voice: <strong className="text-amber-300">{selectedVoiceName || 'British AI Butler'}</strong></span>
                    <span>•</span>
                    <span>Rate: <strong className="text-cyan-300">{speed}x</strong></span>
                  </div>
                </div>
              </div>

              {/* Master Playback Controls */}
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  type="button"
                  onClick={() => speechState.isSpeaking ? handlePauseResume() : handlePlay(activeTopic)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-yellow-500 hover:from-red-500 hover:to-yellow-400 text-slate-950 font-black text-xs transition shadow-lg shadow-red-950/80 active:scale-95 cursor-pointer"
                >
                  {speechState.isSpeaking && !speechState.isPaused ? (
                    <>
                      <Pause className="w-4 h-4 fill-slate-950" />
                      <span>Pause Speech</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-slate-950" />
                      <span>{speechState.isPaused ? 'Resume Audio' : 'Play Audio Briefing'}</span>
                    </>
                  )}
                </button>

                {speechState.isSpeaking && (
                  <button
                    type="button"
                    onClick={handleStop}
                    className="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl bg-slate-900 border border-red-500/40 hover:border-red-400 text-red-300 text-xs font-bold transition active:scale-95 cursor-pointer"
                  >
                    <Square className="w-3.5 h-3.5 fill-red-400" />
                    <span>Stop</span>
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => handlePlay(activeTopic)}
                  className="flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-900 border border-white/10 hover:border-amber-400/50 text-slate-300 text-xs font-bold transition active:scale-95 cursor-pointer"
                  title="Replay from beginning"
                >
                  <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                </button>

                {/* Speed Toggle Chips */}
                <div className="flex items-center bg-slate-950/80 p-1 rounded-xl border border-white/10 text-[11px] font-mono font-bold">
                  {[0.85, 1.0, 1.25].map(s => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => handleSpeedChange(s)}
                      className={`px-2 py-1 rounded-lg transition cursor-pointer ${
                        speed === s 
                          ? 'bg-amber-500 text-slate-950 font-black shadow-sm' 
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {s}x
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Optional Voice Selector Dropdown */}
            {voices.length > 0 && (
              <div className="mt-4 pt-3 border-t border-amber-900/30 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <span className="text-slate-400 font-mono text-[11px]">Select AI Accent / Synthesizer:</span>
                <select
                  value={selectedVoiceName}
                  onChange={handleVoiceChange}
                  className="bg-slate-950 border border-amber-500/30 text-amber-200 text-xs rounded-xl px-3 py-1.5 focus:outline-none focus:border-amber-400 font-mono cursor-pointer max-w-sm"
                >
                  {voices.map(v => (
                    <option key={v.name} value={v.name}>
                      {v.name} ({v.lang})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Topic Selectors: 4 Distinct Audio Guides */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              {
                id: 'full' as Topic,
                label: '1. Master Briefing',
                subtitle: 'File + System + Fixes',
                icon: Bot,
                badge: 'Recommended',
                accent: 'border-amber-500/50 text-amber-300'
              },
              {
                id: 'file' as Topic,
                label: '2. Malicious File',
                subtitle: 'Score, YARA & MITRE',
                icon: ShieldAlert,
                badge: `${report?.threat_scoring.threat_score ?? 98}/100`,
                accent: 'border-red-500/50 text-red-400'
              },
              {
                id: 'system' as Topic,
                label: '3. Host System Audit',
                subtitle: 'PIDs, Memory, Regs',
                icon: MonitorCheck,
                badge: `${hostAssessment?.health_score ?? 85}/100`,
                accent: 'border-cyan-500/50 text-cyan-300'
              },
              {
                id: 'solution' as Topic,
                label: '4. Solution & Fixes',
                subtitle: 'Tactical Mitigation',
                icon: ShieldCheck,
                badge: `${hostAssessment?.remediation_plan?.length ?? 4} Steps`,
                accent: 'border-emerald-500/50 text-emerald-300'
              }
            ].map(tab => {
              const Icon = tab.icon;
              const isSelected = activeTopic === tab.id;
              const isCurrentlySpeakingThis = speechState.isSpeaking && speechState.activeTopic === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setActiveTopic(tab.id);
                    handlePlay(tab.id);
                  }}
                  className={`p-3.5 rounded-2xl text-left border transition-all duration-200 cursor-pointer relative overflow-hidden group ${
                    isSelected 
                      ? 'bg-[#220a0e] border-amber-400 ring-1 ring-amber-400/40 shadow-lg shadow-red-950/70 scale-[1.01]' 
                      : 'glass-card border-white/10 hover:border-amber-500/40 hover:bg-white/[0.03]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className={`p-1.5 rounded-lg bg-slate-900 border border-white/10 ${tab.accent}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-[10px] font-mono font-black uppercase px-2 py-0.5 rounded-md bg-slate-900 text-slate-300 border border-white/10">
                      {tab.badge}
                    </span>
                  </div>
                  <div className="font-bold text-xs text-white group-hover:text-amber-200 transition">
                    {tab.label}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    {tab.subtitle}
                  </div>

                  {isCurrentlySpeakingThis && !speechState.isPaused && (
                    <div className="mt-2 flex items-center gap-1 text-[10px] text-cyan-400 font-mono font-bold">
                      <Volume2 className="w-3 h-3 animate-pulse" />
                      <span>Speaking now...</span>
                    </div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Real-Time Live Teleprompter / Subtitles Screen */}
          <div className="glass-card rounded-2xl p-5 border border-amber-900/40 bg-[#090203]/90 relative">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
                  Live Vocal Script &amp; Teleprompter
                </span>
              </div>
              <button
                type="button"
                onClick={handleCopyScript}
                className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-white bg-slate-900 px-2.5 py-1 rounded-lg border border-white/10 hover:border-amber-400 transition cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-amber-400" />}
                <span>{copied ? 'Copied to Clipboard' : 'Copy Script'}</span>
              </button>
            </div>

            <div 
              ref={teleprompterRef}
              className="max-h-44 overflow-y-auto pr-2 space-y-2 text-xs leading-relaxed font-sans text-slate-300 bg-[#050102] p-4 rounded-xl border border-white/[0.06] shadow-inner select-text"
            >
              {currentScript.split('. ').map((sentence, idx) => {
                const clean = sentence.trim() + '.';
                const isActiveSentence = speechState.isSpeaking && speechState.currentText.includes(clean);
                return (
                  <p 
                    key={idx} 
                    className={`transition-colors duration-200 ${
                      isActiveSentence ? 'text-amber-200 font-medium' : 'text-slate-400'
                    }`}
                  >
                    {clean}
                  </p>
                );
              })}
            </div>
          </div>

          {/* 3 Executive Briefing Highlights (File, System, Solutions) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Card 1: What is Malicious in File */}
            <div className="glass-card p-4 rounded-2xl border border-red-500/30 bg-[#160507]/60 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-xs text-red-400 font-black mb-2">
                  <span className="flex items-center gap-1.5 uppercase">
                    <ShieldAlert className="w-4 h-4 text-red-400" /> Malicious In File
                  </span>
                  <span className="font-mono text-slate-200">{report?.sample_name || 'payload.exe'}</span>
                </div>
                <div className="text-xl font-mono font-black text-red-400">
                  {report?.threat_scoring.threat_score ?? 98}/100
                </div>
                <p className="text-[11px] text-slate-300 mt-1 font-medium">
                  {report?.threat_scoring.verdict || 'Confirmed Weaponized Binary'}
                </p>
                <div className="mt-3 space-y-1.5 text-[10px] text-slate-400 font-mono">
                  {report?.threat_scoring.risk_factors?.slice(0, 2).map((rf, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <span className="text-red-400 font-bold">&bull;</span>
                      <span>{rf}</span>
                    </div>
                  ))}
                </div>
              </div>

              {onNavigateTab && (
                <button
                  type="button"
                  onClick={() => {
                    jarvisVoice.stop();
                    onClose();
                    onNavigateTab('overview');
                  }}
                  className="mt-4 w-full py-1.5 px-3 rounded-xl bg-red-950/80 hover:bg-red-900 border border-red-500/40 text-red-200 text-xs font-bold flex items-center justify-center gap-1.5 transition cursor-pointer"
                >
                  <span>Examine File Forensics</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Card 2: What is Malicious on Host System */}
            <div className="glass-card p-4 rounded-2xl border border-cyan-500/30 bg-[#06101c]/60 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-xs text-cyan-400 font-black mb-2">
                  <span className="flex items-center gap-1.5 uppercase">
                    <MonitorCheck className="w-4 h-4 text-cyan-400" /> Malicious On System
                  </span>
                  <span className="font-mono text-slate-200">{hostAssessment?.host_info?.hostname || 'LOCAL HOST'}</span>
                </div>
                <div className="text-xl font-mono font-black text-cyan-300">
                  {hostAssessment?.health_score ?? 85}/100
                </div>
                <p className="text-[11px] text-slate-300 mt-1 font-medium">
                  Alert Status: <strong className="text-amber-400">{hostAssessment?.alert_level || 'ELEVATED'}</strong>
                </p>
                <div className="mt-3 space-y-1.5 text-[10px] text-slate-400 font-mono">
                  {hostAssessment?.active_threats?.filter(t => t.is_suspicious).slice(0, 2).map((t, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <span className="text-cyan-400 font-bold">&bull;</span>
                      <span className="truncate">PID {t.pid}: {t.anomaly_reason}</span>
                    </div>
                  ))}
                  {(!hostAssessment || hostAssessment.active_threats.filter(t => t.is_suspicious).length === 0) && (
                    <div className="text-slate-500">No rogue processes currently detected in host memory.</div>
                  )}
                </div>
              </div>

              {onNavigateTab && (
                <button
                  type="button"
                  onClick={() => {
                    jarvisVoice.stop();
                    onClose();
                    onNavigateTab('host');
                  }}
                  className="mt-4 w-full py-1.5 px-3 rounded-xl bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-200 text-xs font-bold flex items-center justify-center gap-1.5 transition cursor-pointer"
                >
                  <span>Examine System Health</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Card 3: Recommended Solution & Action Plan */}
            <div className="glass-card p-4 rounded-2xl border border-emerald-500/30 bg-[#06180e]/60 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-xs text-emerald-400 font-black mb-2">
                  <span className="flex items-center gap-1.5 uppercase">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" /> Recommended Solution
                  </span>
                  <span className="font-mono text-emerald-300">{hostAssessment?.remediation_plan?.length || 4} Steps</span>
                </div>
                <div className="text-xl font-mono font-black text-emerald-300">
                  Tactical Fix
                </div>
                <p className="text-[11px] text-slate-300 mt-1 font-medium">
                  Prioritized Machine Sanitization
                </p>
                <div className="mt-3 space-y-1.5 text-[10px] text-slate-400 font-mono">
                  {hostAssessment?.remediation_plan?.slice(0, 2).map((item, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <span className="text-emerald-400 font-bold">{i + 1}.</span>
                      <span className="truncate">{item.action}</span>
                    </div>
                  ))}
                  {(!hostAssessment?.remediation_plan || hostAssessment.remediation_plan.length === 0) && (
                    <>
                      <div className="flex items-start gap-1.5"><span className="text-emerald-400">1.</span> Sever network adapters</div>
                      <div className="flex items-start gap-1.5"><span className="text-emerald-400">2.</span> Terminate rogue PID threads</div>
                    </>
                  )}
                </div>
              </div>

              {onNavigateTab && (
                <button
                  type="button"
                  onClick={() => {
                    jarvisVoice.stop();
                    onClose();
                    onNavigateTab('host');
                  }}
                  className="mt-4 w-full py-1.5 px-3 rounded-xl bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-200 text-xs font-bold flex items-center justify-center gap-1.5 transition cursor-pointer"
                >
                  <span>Execute Solution Steps</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-amber-900/40 bg-[#120406] flex items-center justify-between text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span>J.A.R.V.I.S. VOCAL NEURAL SYNTHESIZER ONLINE</span>
          </div>
          <button
            type="button"
            onClick={() => {
              cyberAudio.playClick();
              jarvisVoice.stop();
              onClose();
            }}
            className="px-4 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-white/10 hover:border-amber-400/50 text-xs font-bold transition cursor-pointer"
          >
            Dismiss Guide
          </button>
        </div>
      </div>
    </div>
  );
};
