import React, { useState } from 'react';
import { FullAnalysisReport, HostAssessment } from '../types';
import { SectionGuide } from './SectionGuide';
import { MalwareEradicationRoadmap } from './MalwareEradicationRoadmap';
import { jarvisVoice } from '../utils/jarvisVoice';
import { cyberAudio } from '../utils/cyberAudio';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, RefreshCw, Cpu, HardDrive, 
  AlertOctagon, Terminal, CheckCircle2, TrendingUp, Wrench, Package, Radio, 
  Shield, Server, ArrowUpRight, Zap, Bot
} from 'lucide-react';

interface Props {
  assessment: HostAssessment | null;
  loading: boolean;
  onRescan: () => void;
  report?: FullAnalysisReport | null;
  onOpenJarvisChat?: (promptText?: string) => void;
}

export const SystemAssessmentTab: React.FC<Props> = ({ 
  assessment, 
  loading, 
  onRescan,
  report,
  onOpenJarvisChat
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'vulns' | 'processes' | 'forecast' | 'remediation'>('overview');

  if (loading) {
    return (
      <div className="glass-panel p-16 rounded-3xl flex flex-col items-center justify-center space-y-6 shadow-2xl relative overflow-hidden border border-orange-500/30">
        <div className="absolute inset-0 bg-gradient-to-b from-orange-600/15 via-amber-900/10 to-transparent animate-pulse" />
        <div className="relative">
          <div className="w-20 h-20 rounded-full border-4 border-orange-500/20 border-t-orange-400 animate-spin flex items-center justify-center shadow-xl shadow-orange-950/50" />
          <Radio className="w-8 h-8 text-orange-400 absolute inset-0 m-auto animate-ping opacity-75" />
        </div>
        <div className="text-center space-y-1.5 z-10">
          <div className="text-lg font-black tracking-wide text-white">Performing Deep Host Security Auto-Assessment...</div>
          <div className="text-xs text-orange-300/80 font-mono">
            Scanning runtime processes, registry persistence keys, and auditing installed packages against NVD CVEs...
          </div>
        </div>
      </div>
    );
  }

  if (!assessment) {
    return (
      <div className="glass-card p-12 rounded-3xl text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto" />
        <div className="text-lg font-bold text-slate-200">No Assessment Data Available</div>
        <button
          onClick={onRescan}
          className="px-5 py-2.5 bg-gradient-to-r from-orange-600 via-amber-600 to-orange-500 hover:from-orange-500 hover:to-amber-500 text-white font-black text-xs rounded-xl transition shadow-lg shadow-orange-950/50"
        >
          Initiate Auto-Assessment Now
        </button>
      </div>
    );
  }

  const { host_info, health_score, status, status_color, summary, active_threats, software_audit, threat_forecast, remediation_plan } = assessment;
  const safeThreats: any[] = Array.isArray(active_threats) ? active_threats : ((active_threats as any)?.suspicious_processes || []);

  // Circumference for radial circle SVG
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (health_score / 100) * circumference;

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="System Auto-Assessment &amp; Live Host Posture"
        badge="Live Endpoint Defense"
        whatItDoes="Automatically analyzes the machine on which Pasha is executing. It performs non-intrusive runtime inspection of running operating system processes, checks Windows Registry startup RunKeys for hidden persistence payloads, audits all installed third-party software packages against known National Vulnerability Database (NVD) CVE entries, and builds a predictive attack forecast."
        howItHelps="Unlike traditional malware tools where you must manually find and upload suspicious files, this engine acts as an immediate self-auditor. It proactively alerts you if background coinminers, unpatched browser zero-days, or persistence backdoors are already active on your PC before they can cause data exfiltration or ransomware encryption."
        keyIndicators={[
          { label: "Health Score < 60", detail: "Indicates critical active risks such as suspicious temp processes or high CVSS CVEs", severity: "critical" },
          { label: "Temp Executables", detail: "Processes executing from AppData\\Local\\Temp or Downloads indicate dropped trojans", severity: "critical" },
          { label: "High CVSS CVEs", detail: "Installed browsers or runtimes with active public exploits in the NVD catalog", severity: "high" },
          { label: "RunKey Persistence", detail: "Software configuring registry autostart without administrative signing", severity: "high" },
          { label: "Clean Host (Score > 85)", detail: "No anomaly processes, patched software packages, and minimal attack surface", severity: "info" }
        ]}
        analystTip="Click 'Re-scan Host' at any time to re-evaluate system integrity in <1.1 seconds after applying patches or terminating suspicious tasks."
        defaultExpanded={false}
      />

      {/* Hero Health Banner */}
      <div 
        className="glass-panel p-6 sm:p-7 rounded-3xl relative overflow-hidden border border-white/[0.1] shadow-2xl transition-all"
        style={{
          boxShadow: `0 0 45px ${status_color}20`
        }}
      >
        <div 
          className="absolute -right-20 -top-20 w-80 h-80 rounded-full blur-3xl opacity-20 pointer-events-none"
          style={{ backgroundColor: status_color }}
        />

        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          <div className="flex items-start sm:items-center gap-5">
            {/* Health Score Radial Circle */}
            <div className="relative w-24 h-24 shrink-0 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  className="stroke-slate-800"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  stroke={status_color}
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-xl font-black font-mono tracking-tight text-white">
                  {health_score}
                </span>
                <span className="text-[8px] font-mono text-slate-400 uppercase tracking-widest">
                  / 100
                </span>
              </div>
            </div>

            {/* Health Verdict Information */}
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span 
                  className="px-2.5 py-0.5 text-xs font-black uppercase rounded-full tracking-wider text-slate-950 shadow-md"
                  style={{ backgroundColor: status_color }}
                >
                  {status}
                </span>
                <span className="text-xs font-mono text-slate-400 bg-slate-900/90 px-2.5 py-0.5 rounded-lg border border-white/[0.06]">
                  HOST: {host_info.hostname}
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  ARCH: {host_info.architecture}
                </span>
              </div>

              <h2 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
                Live Host Security Assessment
              </h2>

              <p className="text-xs text-slate-400 font-medium">
                Operating System: <strong className="text-slate-200">{host_info.os}</strong> &bull; Scanned: <strong className="text-orange-400">{summary.total_processes_scanned} Processes</strong> &bull; <strong className="text-amber-300">{summary.installed_software_scanned} Software Packages</strong>
              </p>
            </div>
          </div>

          <div className="flex flex-wrap sm:flex-col gap-2 shrink-0">
            <button
              onClick={() => {
                cyberAudio.playClick();
                jarvisVoice.speak(jarvisVoice.generateSystemScript(assessment), 'system');
              }}
              className="flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-red-600/30 via-amber-600/30 to-cyan-500/30 hover:from-red-600/50 hover:to-cyan-500/50 text-amber-200 hover:text-white font-bold text-xs rounded-xl border border-amber-500/50 hover:border-amber-400 transition shadow-lg shadow-red-950/40 cursor-pointer"
            >
              <Bot className="w-4 h-4 text-cyan-400" />
              <span>Hear J.A.R.V.I.S. Host Diagnosis</span>
            </button>

            <button
              onClick={onRescan}
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-gradient-to-r from-red-600 via-amber-600 to-yellow-500 hover:from-red-500 hover:to-yellow-400 text-slate-950 font-black text-xs rounded-xl transition shadow-lg shadow-red-950/60 shrink-0 cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" /> <span>Re-scan Host</span>
            </button>
          </div>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div 
          onClick={() => setActiveSubTab('processes')}
          className="glass-card p-4 rounded-2xl cursor-pointer group hover:border-orange-500/50 hover:shadow-orange-950/30"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase mb-1">
            <span className="group-hover:text-orange-400 transition">Running Processes</span>
            <Cpu className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-black font-mono text-white">
            {summary.total_processes_scanned}
          </div>
          <div className="text-xs mt-1">
            {summary.suspicious_processes > 0 ? (
              <span className="text-rose-400 font-bold">{summary.suspicious_processes} Suspicious Anomaly</span>
            ) : (
              <span className="text-emerald-400 font-bold">Verified Benign</span>
            )}
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('vulns')}
          className="glass-card p-4 rounded-2xl cursor-pointer group hover:border-amber-500/50"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase mb-1">
            <span className="group-hover:text-amber-300 transition">Known CVEs Found</span>
            <AlertOctagon className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black font-mono text-amber-400">
            {summary.known_vulnerabilities_detected}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Across {summary.installed_software_scanned} audited packages
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('forecast')}
          className="glass-card p-4 rounded-2xl cursor-pointer group hover:border-purple-500/50"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase mb-1">
            <span className="group-hover:text-purple-300 transition">Forecasted Vectors</span>
            <TrendingUp className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black font-mono text-purple-300">
            {threat_forecast.length} Scenarios
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Predictive threat vectors modeled
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('remediation')}
          className="glass-card p-4 rounded-2xl cursor-pointer group hover:border-emerald-500/50"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase mb-1">
            <span className="group-hover:text-emerald-300 transition">Required Fixes</span>
            <Wrench className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black font-mono text-emerald-300">
            {remediation_plan.length} Actions
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Prioritized remediation steps
          </div>
        </div>
      </div>

      {/* Sub-Navigation Buttons */}
      <div className="flex flex-wrap gap-2 glass-panel p-1.5 rounded-2xl border border-orange-900/40 text-xs font-bold shadow-lg">
        {[
          { id: 'overview', label: 'Overview & Alerts', icon: ShieldCheck },
          { id: 'vulns', label: `Software CVEs (${software_audit.vulnerability_count})`, icon: Package },
          { id: 'processes', label: `Host Processes (${summary.total_processes_scanned})`, icon: Cpu },
          { id: 'forecast', label: `Predictive Threat Forecast (${threat_forecast.length})`, icon: TrendingUp },
          { id: 'remediation', label: `Remediation Plan (${remediation_plan.length})`, icon: Wrench },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl transition-all ${
                isActive
                  ? 'bg-gradient-to-r from-orange-600 via-amber-600 to-orange-500 text-white font-black shadow-md shadow-orange-950/50'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Viewport: Overview */}
      {activeSubTab === 'overview' && (
        <div className="space-y-6">
          {safeThreats.length > 0 && (
            <div className="bg-rose-950/40 border border-rose-500/60 p-5 rounded-3xl space-y-3 shadow-xl shadow-rose-950/20">
              <div className="flex items-center gap-2 text-rose-300 font-extrabold text-sm">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span>ALERT: Suspicious Malware Process Signatures Operating on Host!</span>
              </div>
              <div className="space-y-2">
                {safeThreats.map((t, idx) => (
                  <div key={idx} className="bg-slate-950/90 p-3.5 rounded-2xl border border-rose-900/60 text-xs font-mono flex justify-between items-center">
                    <div>
                      <span className="text-rose-400 font-bold">{t.name} (PID: {t.pid})</span>
                      <div className="text-slate-400 mt-0.5">{t.path}</div>
                      <div className="text-amber-400 mt-0.5">{t.anomaly_reason}</div>
                    </div>
                    <span className="px-2.5 py-1 bg-rose-900 text-rose-200 text-[10px] font-bold rounded-lg">
                      CRITICAL RISK
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {/* Active Process Threat Detection */}
          <div className="glass-card p-6 rounded-3xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl ${safeThreats.length > 0 ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                  {safeThreats.length > 0 ? <AlertOctagon className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
                </div>
                <div>
                  <h3 className="text-sm font-extrabold text-white">
                    {safeThreats.length > 0 ? 'Suspicious Live Processes Detected' : 'Live Host Processes: Clean & Verified'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {safeThreats.length > 0
                      ? 'Process paths originating from Temp/Downloads or unrecognized binaries'
                      : 'All active process binaries verified against known OS signatures'}
                  </p>
                </div>
              </div>
              <span className={`px-3 py-1 rounded-xl text-xs font-mono font-bold ${
                safeThreats.length > 0 
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60' 
                  : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
              }`}>
                {safeThreats.length} Flagged
              </span>
            </div>

            {safeThreats.length > 0 && (
              <div className="overflow-x-auto border border-rose-900/30 rounded-2xl bg-rose-950/10">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-rose-950/40 text-rose-300/80 border-b border-rose-900/30">
                    <tr>
                      <th className="p-3">PID</th>
                      <th className="p-3">Process Name</th>
                      <th className="p-3">Executable Path</th>
                      <th className="p-3">Anomaly Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-rose-900/20">
                    {safeThreats.map((t, idx) => (
                      <tr key={idx} className="hover:bg-rose-900/20 transition">
                        <td className="p-3 text-rose-300 font-bold">{t.pid}</td>
                        <td className="p-3 text-white font-bold">{t.name}</td>
                        <td className="p-3 text-slate-300 break-all text-[11px]">{t.path}</td>
                        <td className="p-3 text-rose-400 font-bold text-[11px]">{t.anomaly_reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Vulnerable Software Overview */}
          <div className="glass-card p-6 rounded-3xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-400">
                  <Package className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-extrabold text-white">Critical Software Vulnerabilities (CVEs)</h3>
                  <p className="text-xs text-slate-400">High &amp; Critical CVSS vulnerabilities affecting installed applications</p>
                </div>
              </div>
              <span className="px-3 py-1 rounded-xl text-xs font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                {software_audit.vulnerability_count} CVEs
              </span>
            </div>

            {software_audit.vulnerabilities.length === 0 ? (
              <div className="p-6 bg-slate-950/60 rounded-2xl text-center text-emerald-400 text-xs border border-emerald-500/20">
                No known critical or high severity CVEs detected across installed software packages.
              </div>
            ) : (
              <div className="space-y-3">
                {software_audit.vulnerabilities.map((v, idx) => (
                  <div key={idx} className="bg-slate-950/80 p-4 rounded-2xl border border-white/[0.05] flex items-start gap-4">
                    <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 shrink-0">
                      <AlertTriangle className="w-4 h-4" />
                    </div>
                    <div className="space-y-1 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-white text-sm">{v.software}</span>
                        <span className="px-2 py-0.5 bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-mono font-bold rounded-md">
                          {v.cve}
                        </span>
                        <span className="px-2 py-0.5 bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-mono font-bold rounded-md">
                          CVSS {v.cvss} ({v.severity})
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1">{v.description}</p>
                      <p className="text-xs text-rose-400 font-semibold mt-1">Recommended Action: {v.remediation}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Viewport: Software Vulnerabilities */}
      {activeSubTab === 'vulns' && (
        <div className="glass-card p-6 rounded-3xl space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                <Package className="w-4 h-4 text-amber-400" /> Audited Installed System Packages
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Cross-referenced against NIST NVD and Known Exploited Vulnerabilities catalog
              </p>
            </div>
            <span className="text-xs font-mono text-orange-300 font-bold bg-orange-950/80 px-3 py-1 rounded-xl border border-orange-800/50">
              {software_audit.total_software_found} Packages Audited
            </span>
          </div>

          <div className="overflow-x-auto border border-white/[0.06] rounded-2xl">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-white/[0.06]">
                <tr>
                  <th className="p-3.5">Application Name</th>
                  <th className="p-3.5">Installed Version</th>
                  <th className="p-3.5">Publisher</th>
                  <th className="p-3.5">CVE Status</th>
                  <th className="p-3.5">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04] bg-slate-950/40">
                {software_audit.installed_software.map((app, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/60 transition">
                    <td className="p-3.5 font-bold text-slate-200">{app.name}</td>
                    <td className="p-3.5 text-orange-300 font-semibold">{app.version}</td>
                    <td className="p-3.5 text-slate-400">{app.publisher}</td>
                    <td className="p-3.5">
                      {app.has_cve ? (
                        <span className="text-rose-400 font-bold">{app.cve_id}</span>
                      ) : (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Up to Date
                        </span>
                      )}
                    </td>
                    <td className="p-3.5">
                      {app.has_cve ? (
                        <span className="px-2 py-0.5 bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold rounded">
                          {app.severity || 'HIGH'}
                        </span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Viewport: Processes */}
      {activeSubTab === 'processes' && (
        <div className="glass-card p-6 rounded-3xl space-y-4">
          <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-orange-400" /> Monitored Host Processes
          </h3>
          <div className="overflow-x-auto border border-white/[0.06] rounded-2xl">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-white/[0.06]">
                <tr>
                  <th className="p-3.5">PID</th>
                  <th className="p-3.5">Process Name</th>
                  <th className="p-3.5">Path</th>
                  <th className="p-3.5">Audit Assessment</th>
                  <th className="p-3.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04] bg-slate-950/40">
                {safeThreats.length > 0 ? (
                  safeThreats.map((proc: any, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-900/60 transition">
                      <td className="p-3.5 text-slate-400">{proc.pid}</td>
                      <td className="p-3.5 font-bold text-slate-200">{proc.name}</td>
                      <td className="p-3.5 text-slate-400 font-mono text-[11px] truncate max-w-xs">{proc.path || 'N/A'}</td>
                      <td className="p-3.5 text-orange-300">{proc.anomaly_reason || 'Verified system process'}</td>
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                          proc.is_suspicious ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {proc.is_suspicious ? 'SUSPICIOUS' : 'RUNNING'}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="p-6 text-center text-slate-500 italic">
                      No anomalous processes detected. All running host processes verified safe.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Viewport: Predictive Forecast */}
      {activeSubTab === 'forecast' && (
        <div className="glass-card p-6 rounded-3xl space-y-4">
          <div>
            <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-orange-400" /> Predictive Threat Forecast & Attack Vectors
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Heuristic projection of host vulnerability exploitation risks based on system topology
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {threat_forecast.map((fc, idx) => (
              <div key={idx} className="glass-panel p-5 rounded-2xl border border-white/[0.06] space-y-3">
                <div className="flex justify-between items-start">
                  <div className="font-bold text-white text-sm flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: fc.probability === 'CRITICAL' ? '#ef4444' : fc.probability === 'HIGH' ? '#f59e0b' : '#22c55e' }} />
                    {fc.vector}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400">PROBABILITY:</span>
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                      fc.probability === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                      fc.probability === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {fc.probability}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300">{fc.reasoning}</p>

                <div className="bg-slate-900/90 p-3 rounded-xl border border-white/[0.04] text-xs font-mono text-orange-300">
                  <strong className="text-slate-400">Preemptive Defense:</strong> {fc.mitigation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Viewport: Remediation Plan */}
      {activeSubTab === 'remediation' && (
        <div className="space-y-6">
          {/* Complete AI Flowchart Roadmap for Host & File Malware Removal */}
          <MalwareEradicationRoadmap
            report={report || null}
            hostAssessment={assessment}
            onOpenJarvisChat={onOpenJarvisChat}
          />

          <div className="glass-card p-6 rounded-3xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-emerald-400" /> Actionable Vulnerability Remediation Plan
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Step-by-step instructions to harden this host against detected vulnerabilities and active risks
                </p>
              </div>

              <button
                onClick={() => {
                  cyberAudio.playClick();
                  jarvisVoice.speak(jarvisVoice.generateSolutionScript(null, assessment), 'solution');
                }}
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-emerald-600/30 via-teal-600/30 to-cyan-600/30 hover:from-emerald-600/50 hover:to-cyan-600/50 text-emerald-200 hover:text-white border border-emerald-500/50 hover:border-emerald-400 rounded-xl text-xs font-bold transition shadow-sm cursor-pointer shrink-0"
              >
                <Bot className="w-4 h-4 text-emerald-400" />
                <span>Hear J.A.R.V.I.S. Remediation Guide</span>
              </button>
            </div>

          <div className="space-y-3">
            {remediation_plan.length === 0 ? (
              <div className="p-8 bg-slate-950/80 rounded-2xl text-center text-emerald-400 text-xs border border-emerald-500/30">
                🎉 No immediate remediation required! System is currently in a hardened state.
              </div>
            ) : (
              remediation_plan.map((item, idx) => (
                <div key={idx} className="bg-slate-950/80 p-4 rounded-2xl border border-white/[0.05] flex justify-between items-start gap-4">
                  <div className="space-y-1">
                    <div className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-orange-950 text-orange-400 border border-orange-800/60 text-xs flex items-center justify-center font-mono font-bold">
                        {idx + 1}
                      </span>
                      {item.action}
                    </div>
                    <div className="text-xs text-slate-300 pl-7">{item.details}</div>
                  </div>

                  <span className={`px-2.5 py-1 text-[10px] font-bold rounded whitespace-nowrap ${
                    item.urgency === 'IMMEDIATE' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    item.urgency === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {item.urgency} PRIORITY
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
        </div>
      )}
    </div>
  );
};
