import React, { useState, useEffect } from 'react';
import { FullAnalysisReport, HostAssessment } from '../types';
import { jarvisVoice, JarvisSpeechState } from '../utils/jarvisVoice';
import { cyberAudio } from '../utils/cyberAudio';
import { 
  Bot, Play, Pause, Square, Volume2, ShieldAlert, MonitorCheck, 
  ShieldCheck, Radio, Sparkles, SlidersHorizontal, ArrowUpRight
} from 'lucide-react';

interface JarvisVoiceBannerProps {
  report: FullAnalysisReport | null;
  hostAssessment: HostAssessment | null;
  onOpenModal: () => void;
}

export const JarvisVoiceBanner: React.FC<JarvisVoiceBannerProps> = ({
  report,
  hostAssessment,
  onOpenModal
}) => {
  const [speechState, setSpeechState] = useState<JarvisSpeechState>(jarvisVoice.getState());

  useEffect(() => {
    return jarvisVoice.subscribe(setSpeechState);
  }, []);

  const handlePlayTopic = (topic: 'full' | 'file' | 'system' | 'solution') => {
    cyberAudio.playClick();
    let text = '';
    if (topic === 'file') text = jarvisVoice.generateFileScript(report);
    else if (topic === 'system') text = jarvisVoice.generateSystemScript(hostAssessment);
    else if (topic === 'solution') text = jarvisVoice.generateSolutionScript(report, hostAssessment);
    else text = jarvisVoice.generateFullScript(report, hostAssessment);

    jarvisVoice.speak(text, topic);
  };

  const handlePauseResume = () => {
    cyberAudio.playClick();
    if (speechState.isPaused) {
      jarvisVoice.resume();
    } else if (speechState.isSpeaking) {
      jarvisVoice.pause();
    } else {
      handlePlayTopic('full');
    }
  };

  const handleStop = () => {
    cyberAudio.playClick();
    jarvisVoice.stop();
  };

  return (
    <div className="relative overflow-hidden rounded-3xl border border-amber-500/40 bg-gradient-to-r from-[#170508]/95 via-[#23080e]/90 to-[#0e0306]/95 p-4 sm:p-5 shadow-2xl shadow-red-950/70 hud-corner">
      {/* Glow highlight */}
      <div className="absolute top-0 right-1/4 w-96 h-28 bg-gradient-to-b from-amber-500/15 via-red-600/10 to-transparent pointer-events-none rounded-full blur-3xl" />

      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10">
        {/* Left info area */}
        <div className="flex items-center gap-3.5">
          <div className="relative shrink-0">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-red-600 via-amber-600 to-yellow-500 flex items-center justify-center text-slate-950 shadow-xl shadow-red-950/80">
              <Bot className="w-6 h-6 stroke-[2.5]" />
            </div>
            {speechState.isSpeaking && !speechState.isPaused && (
              <span className="absolute -top-1 -right-1 flex h-3.5 w-3.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-cyan-400" />
              </span>
            )}
          </div>

          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-mono font-black uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                J.A.R.V.I.S. TACTICAL AUDIO ASSISTANT &amp; GUIDE
              </span>
              <span className="px-2 py-0.5 text-[9px] font-mono font-black uppercase rounded-full bg-red-950/90 text-red-300 border border-red-500/40">
                VOICE AI ONLINE
              </span>
            </div>

            <h3 className="text-sm sm:text-base font-black text-white mt-0.5 tracking-tight flex items-center gap-2">
              <span>Hear Malicious File &amp; System Security Diagnosis</span>
              {speechState.isSpeaking && !speechState.isPaused && (
                <span className="inline-flex items-center gap-0.5 text-cyan-400">
                  <span className="w-1 h-3 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-1 h-4 bg-amber-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-1 h-3 bg-red-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </span>
              )}
            </h3>

            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Listen to an audible briefing on what makes this file malicious, infected host processes, and step-by-step remediation.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
          {/* Main Play/Pause Button */}
          <button
            type="button"
            onClick={handlePauseResume}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-yellow-500 hover:from-red-500 hover:to-yellow-400 text-slate-950 font-black text-xs transition shadow-lg shadow-red-950/80 active:scale-95 cursor-pointer"
          >
            {speechState.isSpeaking && !speechState.isPaused ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-slate-950" />
                <span>Pause Briefing</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                <span>{speechState.isPaused ? 'Resume Briefing' : '🎙️ Listen to Audio Briefing'}</span>
              </>
            )}
          </button>

          {/* Stop button when speaking */}
          {speechState.isSpeaking && (
            <button
              type="button"
              onClick={handleStop}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 border border-red-500/40 text-red-300 text-xs font-bold transition active:scale-95 cursor-pointer"
            >
              <Square className="w-3 h-3 fill-red-400" />
              <span>Stop</span>
            </button>
          )}

          {/* Quick topic buttons */}
          <button
            type="button"
            onClick={() => handlePlayTopic('file')}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition cursor-pointer border ${
              speechState.isSpeaking && speechState.activeTopic === 'file'
                ? 'bg-red-950/90 border-red-400 text-white shadow-md'
                : 'bg-slate-900/80 hover:bg-slate-800 border-white/10 hover:border-red-400/50 text-slate-300'
            }`}
            title="Hear forensic breakdown of the malicious file"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>Malicious File</span>
          </button>

          <button
            type="button"
            onClick={() => handlePlayTopic('system')}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition cursor-pointer border ${
              speechState.isSpeaking && speechState.activeTopic === 'system'
                ? 'bg-cyan-950/90 border-cyan-400 text-white shadow-md'
                : 'bg-slate-900/80 hover:bg-slate-800 border-white/10 hover:border-cyan-400/50 text-slate-300'
            }`}
            title="Hear host system anomalies and suspicious processes"
          >
            <MonitorCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>Host Threats</span>
          </button>

          <button
            type="button"
            onClick={() => handlePlayTopic('solution')}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition cursor-pointer border ${
              speechState.isSpeaking && speechState.activeTopic === 'solution'
                ? 'bg-emerald-950/90 border-emerald-400 text-white shadow-md'
                : 'bg-slate-900/80 hover:bg-slate-800 border-white/10 hover:border-emerald-400/50 text-slate-300'
            }`}
            title="Hear recommended solutions and cleanup steps"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Recommended Solution</span>
          </button>

          {/* Open Full Guide & Teleprompter Console */}
          <button
            type="button"
            onClick={() => {
              cyberAudio.playClick();
              onOpenModal();
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-950/60 hover:bg-amber-900/70 border border-amber-500/40 text-amber-300 hover:text-white text-xs font-bold transition active:scale-95 cursor-pointer ml-auto lg:ml-0"
            title="Open J.A.R.V.I.S. Audio Guide & Teleprompter Console"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>Full Guide Console</span>
          </button>
        </div>
      </div>
    </div>
  );
};
