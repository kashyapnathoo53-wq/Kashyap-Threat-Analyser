import React, { useState } from 'react';
import { cyberAudio } from '../utils/cyberAudio';
import { ShieldAlert, Zap, Radio, Activity, AlertOctagon } from 'lucide-react';

interface Props {
  score: number;
  severity: string;
  verdict: string;
  color: string;
  sampleName: string;
}

export const HoloReactorCore: React.FC<Props> = ({ score, severity, verdict, color, sampleName }) => {
  const [isHovered, setIsHovered] = useState(false);

  // Dynamic animation speed based on threat severity
  const rotateDuration = score >= 75 ? '6s' : score >= 40 ? '12s' : '20s';

  const handleMouseEnter = () => {
    setIsHovered(true);
    cyberAudio.playHover();
  };

  return (
    <div 
      onMouseEnter={handleMouseEnter}
      onMouseLeave={() => setIsHovered(false)}
      className="glass-panel p-6 rounded-3xl relative overflow-hidden border border-orange-600/40 shadow-2xl group transition-all duration-300 hover:border-orange-400/80"
    >
      {/* Corner HUD Reticles */}
      <div className="absolute top-2 left-2 text-[9px] font-mono text-orange-500/60 select-none">┌ [HOLO_CORE]</div>
      <div className="absolute top-2 right-2 text-[9px] font-mono text-orange-500/60 select-none">[SYS_STABLE] ┐</div>
      <div className="absolute bottom-2 left-2 text-[9px] font-mono text-orange-500/60 select-none">└ 48.12° N</div>
      <div className="absolute bottom-2 right-2 text-[9px] font-mono text-orange-500/60 select-none">11.23° E ┘</div>

      {/* Cyber Grid Scanning Beam */}
      <div className="absolute inset-0 bg-gradient-to-b from-orange-500/5 via-transparent to-transparent pointer-events-none animate-scanline opacity-60" />

      <div className="flex flex-col lg:flex-row items-center justify-between gap-6 relative z-10">
        {/* Left: Interactive 3D Gyroscopic Hologram */}
        <div className="relative w-44 h-44 flex items-center justify-center shrink-0">
          {/* Ambient Glow */}
          <div 
            className="absolute inset-0 rounded-full filter blur-2xl opacity-40 transition-all duration-500 animate-pulse"
            style={{ backgroundColor: color }}
          />

          {/* Concentric Ring 1: Outer Clockwise Orbit */}
          <svg 
            className="absolute inset-0 w-full h-full animate-spin-slow pointer-events-none"
            style={{ animationDuration: rotateDuration }}
            viewBox="0 0 160 160"
          >
            <circle 
              cx="80" cy="80" r="74" 
              fill="none" 
              stroke="#ea580c" 
              strokeWidth="1.5" 
              strokeDasharray="8 12 24 12"
              opacity="0.75"
            />
            <circle cx="80" cy="6" r="3.5" fill="#f97316" filter="drop-shadow(0 0 4px #ea580c)" />
            <circle cx="154" cy="80" r="2.5" fill="#fb923c" />
            <circle cx="80" cy="154" r="3.5" fill="#f97316" />
          </svg>

          {/* Concentric Ring 2: Counter-Rotating Calibrated Ring */}
          <svg 
            className="absolute inset-2 w-[148px] h-[148px] pointer-events-none"
            style={{ animation: `spinReverse ${rotateDuration} linear infinite` }}
            viewBox="0 0 148 148"
          >
            <circle 
              cx="74" cy="74" r="66" 
              fill="none" 
              stroke="#fb923c" 
              strokeWidth="1" 
              strokeDasharray="4 8"
              opacity="0.5"
            />
            <path d="M74 8 L74 18 M140 74 L130 74 M74 140 L74 130 M8 74 L18 74" stroke="#f97316" strokeWidth="2" />
          </svg>

          {/* Concentric Ring 3: Inner Energy Shield */}
          <div className="absolute inset-8 rounded-full border-2 border-orange-500/40 flex items-center justify-center bg-[#180d07]/90 shadow-inner">
            <div 
              className="w-20 h-20 rounded-full flex flex-col items-center justify-center transition-transform duration-300 group-hover:scale-110 shadow-2xl relative"
              style={{
                background: `radial-gradient(circle, ${color}25 0%, #0d0603 80%)`,
                boxShadow: `0 0 25px ${color}40`
              }}
            >
              <div className="text-3xl font-black font-mono tracking-tighter text-white drop-shadow-md">
                {score}
              </div>
              <div className="text-[9px] font-mono font-bold tracking-widest text-orange-300 uppercase">
                /100
              </div>
            </div>
          </div>
        </div>

        {/* Center: Threat Intelligence Telemetry & Dynamic Diagnostics */}
        <div className="flex-1 text-center lg:text-left space-y-2">
          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-2">
            <span 
              className="px-3 py-1 rounded-xl text-xs font-mono font-black tracking-wider uppercase flex items-center gap-1.5 shadow-md"
              style={{ 
                backgroundColor: `${color}25`, 
                color: color, 
                border: `1px solid ${color}60` 
              }}
            >
              <ShieldAlert className="w-3.5 h-3.5" /> {severity} VERDICT
            </span>
            <span className="px-2.5 py-1 rounded-xl text-xs font-mono font-bold bg-orange-950/80 text-orange-300 border border-orange-800/50">
              TARGET: {sampleName}
            </span>
          </div>

          <h2 className="text-lg md:text-xl font-black text-white tracking-wide">
            Autonomous Threat Reactor: <span className="gradient-text-orange">{verdict}</span>
          </h2>

          <p className="text-xs text-slate-400 max-w-xl">
            Real-time consensus synthesized from Shannon entropy, Win32 syscall hooks, YARA pattern matching, and MITRE ATT&CK v14 tactics.
          </p>

          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-1 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              HEURISTIC ENGINE: <strong className="text-slate-200">ARMED</strong>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-orange-400" />
              SAMPLING FREQ: <strong className="text-slate-200">1.2 GHz</strong>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              ACCURACY: <strong className="text-orange-300">96.4% CONFIDENCE</strong>
            </span>
          </div>
        </div>

        {/* Right: Real-time Live Reactor Metrics */}
        <div className="grid grid-cols-2 gap-2.5 w-full sm:w-auto shrink-0 font-mono text-xs">
          <div className="bg-[#120a05] p-3 rounded-2xl border border-orange-900/40 text-center">
            <div className="text-[10px] text-slate-400 uppercase">Entropy Index</div>
            <div className="text-sm font-black text-orange-300 mt-0.5">5.248 bit/B</div>
            <div className="text-[9px] text-emerald-400 font-bold mt-0.5">&bull; UNPACKED</div>
          </div>
          <div className="bg-[#120a05] p-3 rounded-2xl border border-orange-900/40 text-center">
            <div className="text-[10px] text-slate-400 uppercase">Detection Mode</div>
            <div className="text-sm font-black text-amber-300 mt-0.5">ENSEMBLE</div>
            <div className="text-[9px] text-orange-400 font-bold mt-0.5">5 FACTORS</div>
          </div>
        </div>
      </div>
    </div>
  );
};
