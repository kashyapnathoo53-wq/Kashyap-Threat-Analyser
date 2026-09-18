import React, { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp, Shield, Lightbulb, AlertTriangle, CheckCircle2, Sparkles, BookOpen } from 'lucide-react';

interface GuideProps {
  title: string;
  badge?: string;
  whatItDoes: string;
  howItHelps: string;
  keyIndicators: { label: string; detail: string; severity?: 'critical' | 'high' | 'info' }[];
  analystTip?: string;
  defaultExpanded?: boolean;
}

export const SectionGuide: React.FC<GuideProps> = ({
  title,
  badge = "SOC Intelligence Brief",
  whatItDoes,
  howItHelps,
  keyIndicators,
  analystTip,
  defaultExpanded = false
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <div className="glass-card rounded-2xl overflow-hidden border border-white/[0.08] shadow-2xl transition-all duration-300 mb-6 group">
      {/* Header bar */}
      <div 
        role="button"
        tabIndex={0}
        onClick={() => setIsExpanded(!isExpanded)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsExpanded(!isExpanded); } }}
        className="px-5 py-4 flex items-center justify-between cursor-pointer hover:bg-white/[0.04] transition select-none"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-lime-600/20 to-olive-700/30 border border-lime-500/40 flex items-center justify-center text-lime-400 shrink-0 shadow-inner">
            <BookOpen className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h4 className="text-sm font-extrabold text-white tracking-wide">{title}</h4>
              <span className="px-2.5 py-0.5 text-[10px] uppercase font-mono font-black rounded-full bg-olive-950/90 text-lime-300 border border-lime-500/40 shadow-sm">
                {badge}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {isExpanded ? "Click anywhere on this card to minimize" : "Click to expand methodology, threat intelligence value & critical indicators"}
            </p>
          </div>
        </div>

        <button 
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setIsExpanded(!isExpanded);
          }}
          className="text-xs font-mono font-bold text-lime-300 hover:text-white flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-lime-500/30 hover:border-lime-400 hover:bg-olive-950/60 transition shadow-sm cursor-pointer"
        >
          <span>{isExpanded ? "Collapse Guide" : "Read Brief"}</span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Expandable Content Area */}
      {isExpanded && (
        <div className="px-5 pb-5 pt-2 border-t border-white/[0.06] space-y-4 text-xs animate-fadeIn bg-slate-950/40">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* What it does */}
            <div className="glass-card p-4 rounded-xl border border-lime-900/40 bg-slate-900/60">
              <div className="flex items-center gap-2 text-lime-400 font-black mb-2 text-xs uppercase tracking-wider">
                <Shield className="w-4 h-4 text-lime-400" /> What Does This Section Do?
              </div>
              <p className="text-slate-300 leading-relaxed text-[12px]">
                {whatItDoes}
              </p>
            </div>

            {/* How it helps */}
            <div className="glass-card p-4 rounded-xl border border-emerald-900/40 bg-slate-900/60">
              <div className="flex items-center gap-2 text-emerald-300 font-black mb-2 text-xs uppercase tracking-wider">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> How It Helps Security Teams
              </div>
              <p className="text-slate-300 leading-relaxed text-[12px]">
                {howItHelps}
              </p>
            </div>
          </div>

          {/* Key Threat Indicators */}
          <div className="glass-card p-4 rounded-xl border border-white/[0.06] space-y-2.5 bg-slate-900/70">
            <div className="flex items-center gap-2 text-amber-300 font-black text-xs uppercase tracking-wider">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> Critical Indicators &amp; Rules of Thumb
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1">
              {keyIndicators.map((ind, idx) => (
                <div key={idx} className="bg-slate-950/80 p-3 rounded-xl border border-white/[0.05] text-[11px] shadow-sm">
                  <span className={`font-mono font-black block mb-1 ${
                    ind.severity === 'critical' ? 'text-rose-400' :
                    ind.severity === 'high' ? 'text-amber-400' : 'text-lime-300'
                  }`}>
                    {ind.label}
                  </span>
                  <span className="text-slate-300 leading-tight">{ind.detail}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Pro-Tip */}
          {analystTip && (
            <div className="bg-gradient-to-r from-purple-950/50 via-slate-900/60 to-slate-950 p-3.5 rounded-xl border border-purple-500/30 flex items-start gap-3 shadow-lg">
              <div className="w-7 h-7 rounded-lg bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300 shrink-0">
                <Sparkles className="w-3.5 h-3.5" />
              </div>
              <div className="text-[12px] text-purple-200 leading-relaxed">
                <strong className="text-purple-300 font-bold">Forensic Analyst Pro-Tip: </strong>
                {analystTip}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
