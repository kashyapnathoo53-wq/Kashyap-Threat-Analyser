import React from 'react';
import { FullAnalysisReport } from '../types';
import { ShieldAlert, AlertTriangle, ShieldCheck, Activity, Terminal, Database, Layers, CheckCircle2 } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

interface Props {
  report: FullAnalysisReport;
  onNavigateTab: (tab: string) => void;
}

export const DashboardOverview: React.FC<Props> = ({ report, onNavigateTab }) => {
  const threat = report.threat_scoring;
  const score = threat.threat_score;

  const scoreData = [
    { name: 'Static', score: threat.score_breakdown.static_score, max: 25, color: '#3b82f6' },
    { name: 'YARA', score: threat.score_breakdown.yara_score, max: 25, color: '#f59e0b' },
    { name: 'Behavioral', score: threat.score_breakdown.behavioral_score, max: 30, color: '#ef4444' },
    { name: 'IOC Density', score: threat.score_breakdown.ioc_score, max: 10, color: '#10b981' },
    { name: 'MITRE TTPs', score: threat.score_breakdown.mitre_score, max: 10, color: '#8b5cf6' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Threat Verdict Banner */}
      <div 
        className="p-6 rounded-xl border flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xl transition-all"
        style={{
          backgroundColor: '#111827',
          borderColor: threat.color + '66',
          boxShadow: `0 0 30px ${threat.color}22`
        }}
      >
        <div className="flex items-center gap-5">
          <div 
            className="w-20 h-20 rounded-full flex items-center justify-center shrink-0 border-4 shadow-inner"
            style={{ borderColor: threat.color, backgroundColor: threat.color + '15' }}
          >
            {score >= 70 ? (
              <ShieldAlert className="w-10 h-10" style={{ color: threat.color }} />
            ) : score >= 40 ? (
              <AlertTriangle className="w-10 h-10 text-amber-400" />
            ) : (
              <ShieldCheck className="w-10 h-10 text-emerald-400" />
            )}
          </div>

          <div>
            <div className="flex items-center gap-3">
              <span 
                className="px-3 py-1 text-xs font-bold uppercase rounded-full tracking-wider text-white"
                style={{ backgroundColor: threat.color }}
              >
                {threat.severity} SEVERITY
              </span>
              <span className="text-xs font-mono text-slate-400">ID: {report.report_id.slice(0, 16)}</span>
            </div>
            <h2 className="text-2xl font-black text-white mt-1">{threat.verdict}</h2>
            <p className="text-sm text-slate-400 mt-0.5">
              Sample File: <code className="text-cyan-400 font-mono">{report.sample_name}</code> ({report.static_analysis.file_info.type})
            </p>
          </div>
        </div>

        {/* Circular score display */}
        <div className="flex items-center gap-6 bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="text-center">
            <div className="text-4xl font-black font-mono" style={{ color: threat.color }}>
              {score}<span className="text-sm text-slate-500">/100</span>
            </div>
            <div className="text-xs font-semibold text-slate-400 mt-0.5 uppercase tracking-wider">Overall Risk Score</div>
          </div>
        </div>
      </div>

      {/* Quick Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div 
          onClick={() => onNavigateTab('static')}
          className="bg-slate-900/70 border border-slate-800 p-4 rounded-xl hover:border-cyan-500/50 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">PE Entropy</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-300 mt-2">
            {report.static_analysis.file_info.entropy}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Status: {report.static_analysis.pe_structure.is_packed ? 'High (Packed)' : 'Normal (Unpacked)'}
          </div>
        </div>

        <div 
          onClick={() => onNavigateTab('yara')}
          className="bg-slate-900/70 border border-slate-800 p-4 rounded-xl hover:border-amber-500/50 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">YARA Signatures</span>
            <Terminal className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-2">
            {report.yara_scan.match_count} <span className="text-xs text-slate-500 font-normal">Hits</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Rules Scanned: {report.yara_scan.total_rules_scanned}
          </div>
        </div>

        <div 
          onClick={() => onNavigateTab('iocs')}
          className="bg-slate-900/70 border border-slate-800 p-4 rounded-xl hover:border-emerald-500/50 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">Extracted IOCs</span>
            <Database className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-2">
            {report.ioc_extraction.total_extracted} <span className="text-xs text-slate-500 font-normal">Artifacts</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">
            IPs, Hashes, Domains, Registry
          </div>
        </div>

        <div 
          onClick={() => onNavigateTab('mitre')}
          className="bg-slate-900/70 border border-slate-800 p-4 rounded-xl hover:border-purple-500/50 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">MITRE ATT&CK TTPs</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-2">
            {report.mitre_mapping.total_mapped_techniques} <span className="text-xs text-slate-500 font-normal">Techniques</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Mapped across 12 Tactics
          </div>
        </div>
      </div>

      {/* Breakdown Chart & Key Risk Triggers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
          <h3 className="text-base font-bold text-slate-200 mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> Multi-Factor Score Category Breakdown
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scoreData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 12 }} />
                <YAxis stroke="#64748b" domain={[0, 30]} tick={{ fontSize: 12 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc' }}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {scoreData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-200 mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> High Priority Detection Factors
            </h3>
            <div className="space-y-2.5">
              {threat.risk_factors.map((factor, idx) => (
                <div key={idx} className="flex items-start gap-2.5 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 text-sm text-slate-300">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{factor}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-400">
            <span>Kashyap Threat Analyser Sandbox v2.0</span>
            <button 
              onClick={() => onNavigateTab('report')}
              className="text-cyan-400 hover:text-cyan-300 font-semibold underline"
            >
              Export Full Executive Report &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
