import React, { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp, Shield, Lightbulb, AlertTriangle, CheckCircle2 } from 'lucide-react';

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
  badge = "Analyst Intel & Methodology",
  whatItDoes,
  howItHelps,
  keyIndicators,
  analystTip,
  defaultExpanded = false
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <div className="bg-gradient-to-r from-slate-900/95 via-slate-900/80 to-slate-950/95 border border-cyan-500/30 rounded-2xl overflow-hidden shadow-lg shadow-cyan-950/20 backdrop-blur-md mb-6 transition-all duration-300">
      {/* Clickable Header Bar */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        className="px-5 py-3.5 flex items-center justify-between cursor-pointer hover:bg-cyan-500/5 transition select-none"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <HelpCircle className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-bold text-white tracking-wide">{title}</h4>
              <span className="px-2 py-0.5 text-[10px] uppercase font-mono font-bold rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800">
                {badge}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {isExpanded ? "Click to collapse section guide" : "Click to view what this section does, how it protects you, and key indicators"}
            </p>
          </div>
        </div>

        <button 
          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800"
        >
          <span>{isExpanded ? "Hide Guide" : "View Guide"}</span>
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Expandable Body */}
      {isExpanded && (
        <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 space-y-4 text-xs animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* What it does */}
            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800">
              <div className="flex items-center gap-2 text-cyan-300 font-bold mb-1.5 text-xs uppercase tracking-wider">
                <Shield className="w-3.5 h-3.5 text-cyan-400" /> What Does This Section Do?
              </div>
              <p className="text-slate-300 leading-relaxed text-[12px]">
                {whatItDoes}
              </p>
            </div>

            {/* How it helps */}
            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800">
              <div className="flex items-center gap-2 text-emerald-300 font-bold mb-1.5 text-xs uppercase tracking-wider">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> How It Helps You
              </div>
              <p className="text-slate-300 leading-relaxed text-[12px]">
                {howItHelps}
              </p>
            </div>
          </div>

          {/* Key Threat Indicators */}
          <div className="bg-slate-950/90 p-3.5 rounded-xl border border-slate-800/80 space-y-2">
            <div className="flex items-center gap-2 text-amber-300 font-bold text-xs uppercase tracking-wider">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Critical Indicators &amp; Rules of Thumb to Watch
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1">
              {keyIndicators.map((ind, idx) => (
                <div key={idx} className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800 text-[11px]">
                  <span className={`font-mono font-bold block mb-0.5 ${
                    ind.severity === 'critical' ? 'text-rose-400' :
                    ind.severity === 'high' ? 'text-amber-400' : 'text-cyan-300'
                  }`}>
                    {ind.label}
                  </span>
                  <span className="text-slate-300">{ind.detail}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Pro-Tip */}
          {analystTip && (
            <div className="bg-gradient-to-r from-purple-950/40 to-slate-950 p-3 rounded-xl border border-purple-500/30 flex items-start gap-2.5">
              <Lightbulb className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
              <div className="text-[11px] text-purple-200">
                <strong className="text-purple-300">SOC Analyst Pro-Tip: </strong>
                {analystTip}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
