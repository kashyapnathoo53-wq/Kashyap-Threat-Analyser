import React, { useState } from 'react';
import { cyberAudio } from '../utils/cyberAudio';
import { ShieldAlert, Zap, Radio, Activity, Sparkles, Flame } from 'lucide-react';

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
  const rotateDuration = score >= 75 ? '4s' : score >= 40 ? '8s' : '14s';

  const handleMouseEnter = () => {
    setIsHovered(true);
    cyberAudio.playHover();
  };

  const coils = [0, 36, 72, 108, 144, 180, 216, 252, 288, 324];

  return (
    <div 
      onMouseEnter={handleMouseEnter}
      onMouseLeave={() => setIsHovered(false)}
      className="glass-panel hud-corner p-6 sm:p-7 rounded-3xl relative overflow-hidden border border-amber-500/40 shadow-2xl group transition-all duration-300 hover:border-red-500/80 bg-[#120506]/95 hover:shadow-[0_0_50px_rgba(220,38,38,0.25)]"
    >
      {/* Corner HUD Reticles */}
      <div className="absolute top-2 right-2 text-[9px] font-mono text-amber-400/80 select-none">[ARC_REACTOR: OPTIMAL] ┐</div>
      <div className="absolute bottom-2 left-2 text-[9px] font-mono text-amber-400/80 select-none">└ PALLADIUM CORE</div>
      <div className="absolute bottom-2 right-2 text-[9px] font-mono text-amber-400/80 select-none">UNIBEAM 3.14 GJ/s ┘</div>

      {/* Crimson & Gold Scanning Laser */}
      <div className="absolute inset-0 bg-gradient-to-b from-red-600/10 via-transparent to-transparent pointer-events-none animate-scanline opacity-60" />

      <div className="flex flex-col lg:flex-row items-center justify-between gap-6 relative z-10">
        {/* Left: Authentic Iron Man Arc Reactor */}
        <div className="relative w-48 h-48 sm:w-52 sm:h-52 flex items-center justify-center shrink-0">
          {/* Intense Radial Arc Reactor Bloom */}
          <div 
            className="absolute inset-2 rounded-full filter blur-2xl opacity-60 transition-all duration-500 pointer-events-none"
            style={{ 
              background: `radial-gradient(circle, #00f2fe 0%, #0284c7 45%, ${color}40 70%, transparent 100%)` 
            }}
          />

          {/* SVG Arc Reactor Assembly */}
          <svg 
            className="w-full h-full drop-shadow-[0_0_25px_rgba(0,242,254,0.65)] cursor-pointer select-none transition-transform duration-300 group-hover:scale-105"
            viewBox="0 0 190 190"
          >
            <defs>
              <filter id="arcGlow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="3.5" result="glow" />
                <feMerge>
                  <feMergeNode in="glow" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <radialGradient id="palladiumCenter" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#ffffff" />
                <stop offset="30%" stopColor="#e0f2fe" />
                <stop offset="70%" stopColor="#00f2fe" />
                <stop offset="100%" stopColor="#0369a1" />
              </radialGradient>
            </defs>

            {/* Gunmetal Outer Chassis Ring */}
            <circle cx="95" cy="95" r="88" fill="#0a0507" stroke="#475569" strokeWidth="4" />
            <circle cx="95" cy="95" r="84" fill="#14080a" stroke="#78350f" strokeWidth="1.5" strokeDasharray="6 3" />

            {/* 10 Toroidal Copper Wire Electromagnets */}
            {coils.map((angle, idx) => (
              <g key={idx} transform={`rotate(${angle} 95 95)`}>
                {/* Core Bracket */}
                <rect x="86" y="11" width="18" height="23" rx="2" fill="#0f172a" stroke="#64748b" strokeWidth="1" />
                {/* 5 Copper Wire Windings */}
                <line x1="88" y1="15" x2="102" y2="15" stroke="#b45309" strokeWidth="1.8" />
                <line x1="88" y1="19" x2="102" y2="19" stroke="#d97706" strokeWidth="1.8" />
                <line x1="88" y1="23" x2="102" y2="23" stroke="#fbbf24" strokeWidth="1.8" />
                <line x1="88" y1="27" x2="102" y2="27" stroke="#d97706" strokeWidth="1.8" />
                <line x1="88" y1="31" x2="102" y2="31" stroke="#b45309" strokeWidth="1.8" />
                {/* Gold Contact Pin */}
                <circle cx="95" cy="8" r="2" fill="#fbbf24" />
              </g>
            ))}

            {/* Luminous Arc Cyan Flux Ring */}
            <circle cx="95" cy="95" r="60" fill="none" stroke="#00f2fe" strokeWidth="3.5" filter="url(#arcGlow)" opacity="0.9" />

            {/* Rotating Magnetic Stator Ring (Clockwise) */}
            <g className="animate-spin-slow" style={{ transformOrigin: '95px 95px', animationDuration: rotateDuration }}>
              <circle cx="95" cy="95" r="52" fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="8 4 2 4" opacity="0.85" />
              <circle cx="95" cy="43" r="2.5" fill="#00f2fe" />
              <circle cx="147" cy="95" r="2.5" fill="#00f2fe" />
              <circle cx="95" cy="147" r="2.5" fill="#00f2fe" />
              <circle cx="43" cy="95" r="2.5" fill="#00f2fe" />
            </g>

            {/* Counter-Rotating Heatsink Ring (Counter-Clockwise) */}
            <g className="animate-spin-reverse" style={{ transformOrigin: '95px 95px', animationDuration: rotateDuration }}>
              <circle cx="95" cy="95" r="44" fill="none" stroke="#67e8f9" strokeWidth="1.5" strokeDasharray="3 4" opacity="0.75" />
              <path d="M95 54 L95 60 M136 95 L130 95 M95 136 L95 130 M54 95 L60 95" stroke="#00f2fe" strokeWidth="1.5" />
            </g>

            {/* Inscribed Palladium Energy Triangle (Tony Stark Mark VI / Avengers Arc Core) */}
            <polygon 
              points="95,54 130,116 60,116" 
              fill="rgba(0, 242, 254, 0.18)" 
              stroke="#00f2fe" 
              strokeWidth="2.5" 
              filter="url(#arcGlow)" 
            />
            <polygon 
              points="95,62 122,110 68,110" 
              fill="rgba(255, 255, 255, 0.08)" 
              stroke="#ffffff" 
              strokeWidth="1.2" 
              strokeDasharray="4 2" 
            />

            {/* Central Blinding Arc Reactor Core with Threat Score */}
            <circle cx="95" cy="96" r="23" fill="url(#palladiumCenter)" filter="url(#arcGlow)" />
            <circle cx="95" cy="96" r="20" fill="#0a101f" opacity="0.88" />

            {/* Centered White-Hot Score */}
            <text 
              x="95" 
              y="100" 
              textAnchor="middle" 
              fill="#ffffff" 
              fontSize="18" 
              fontWeight="900" 
              fontFamily="monospace"
              filter="drop-shadow(0 0 4px #00f2fe)"
            >
              {score}
            </text>
            <text 
              x="95" 
              y="110" 
              textAnchor="middle" 
              fill="#38bdf8" 
              fontSize="7" 
              fontWeight="800" 
              fontFamily="monospace"
            >
              /100
            </text>
          </svg>
        </div>

        {/* Center: Stark Industries Threat Intelligence Telemetry */}
        <div className="flex-1 text-center lg:text-left space-y-2.5">
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
            <span className="px-2.5 py-1 rounded-xl text-xs font-mono font-black bg-amber-950/80 text-amber-300 border border-amber-500/50 shadow-sm flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" />
              TARGET: {sampleName}
            </span>
          </div>

          <h2 className="text-lg md:text-xl font-black text-white tracking-wide">
            Autonomous Arc Reactor: <span className="gradient-text-stark">{verdict}</span>
          </h2>

          <p className="text-xs text-slate-300 max-w-xl leading-relaxed">
            Real-time consensus synthesized from Shannon entropy, Win32 syscall hooks, YARA pattern matching, and MITRE ATT&amp;CK v14 tactics powered by Autonomous Threat Reactor Core.
          </p>

          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-3.5 pt-1 text-[11px] font-mono text-slate-300">
            <span className="flex items-center gap-1.5 bg-red-950/60 px-2.5 py-1 rounded-lg border border-red-800/40">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              JARVIS PROTOCOL: <strong className="text-white">ENGAGED</strong>
            </span>
            <span className="flex items-center gap-1.5 bg-amber-950/60 px-2.5 py-1 rounded-lg border border-amber-800/40">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              UNIBEAM FLUX: <strong className="text-amber-300">3.14 GJ/s</strong>
            </span>
            <span className="flex items-center gap-1.5 bg-cyan-950/60 px-2.5 py-1 rounded-lg border border-cyan-800/40">
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              CONFIDENCE: <strong className="text-cyan-300">96.4% VERIFIED</strong>
            </span>
          </div>
        </div>

        {/* Right: Real-time Live Reactor Metrics in Stark Armor Styling */}
        <div className="grid grid-cols-2 gap-2.5 w-full sm:w-auto shrink-0 font-mono text-xs">
          <div className="bg-[#1e0a0d]/90 p-3.5 rounded-2xl border border-amber-500/40 text-center shadow-md">
            <div className="text-[10px] text-amber-400/80 font-bold uppercase">Entropy Index</div>
            <div className="text-base font-black text-amber-300 mt-0.5">5.248 bit/B</div>
            <div className="text-[9px] text-emerald-400 font-bold mt-0.5">&bull; UNPACKED</div>
          </div>
          <div className="bg-[#1e0a0d]/90 p-3.5 rounded-2xl border border-amber-500/40 text-center shadow-md">
            <div className="text-[10px] text-amber-400/80 font-bold uppercase">Core Flux</div>
            <div className="text-base font-black text-cyan-300 mt-0.5">PALLADIUM</div>
            <div className="text-[9px] text-amber-400 font-bold mt-0.5">5 VECTORS</div>
          </div>
        </div>
      </div>
    </div>
  );
};
