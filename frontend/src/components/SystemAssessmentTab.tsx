import React, { useState } from 'react';
import { HostAssessment } from '../types';
import { ShieldCheck, ShieldAlert, AlertTriangle, RefreshCw, Cpu, HardDrive, AlertOctagon, Terminal, CheckCircle2, TrendingUp, Wrench, Package } from 'lucide-react';

interface Props {
  assessment: HostAssessment | null;
  loading: boolean;
  onRescan: () => void;
}

export const SystemAssessmentTab: React.FC<Props> = ({ assessment, loading, onRescan }) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'vulns' | 'processes' | 'forecast' | 'remediation'>('overview');

  if (loading) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 p-12 rounded-2xl flex flex-col items-center justify-center space-y-4">
        <RefreshCw className="w-10 h-10 text-cyan-400 animate-spin" />
        <div className="text-base font-bold text-slate-200">Performing Deep Host Security Auto-Assessment...</div>
        <div className="text-xs text-slate-400 font-mono">
          Scanning running system processes, registry RunKeys, installed software versions, and CVE vulnerabilities...
        </div>
      </div>
    );
  }

  if (!assessment) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 p-12 rounded-2xl text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto" />
        <div className="text-lg font-bold text-slate-200">No Assessment Data Available</div>
        <button
          onClick={onRescan}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition"
        >
          Initiate Auto-Assessment Now
        </button>
      </div>
    );
  }

  const { host_info, health_score, status, status_color, summary, active_threats, software_audit, threat_forecast, remediation_plan } = assessment;

  return (
    <div className="space-y-6">
      {/* Host Posture Header Card */}
      <div 
        className="p-6 rounded-2xl border flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xl transition-all"
        style={{
          backgroundColor: '#0f172a',
          borderColor: status_color + '66',
          boxShadow: `0 0 30px ${status_color}18`
        }}
      >
        <div className="flex items-center gap-5">
          <div 
            className="w-20 h-20 rounded-2xl flex items-center justify-center shrink-0 border-2"
            style={{ borderColor: status_color, backgroundColor: status_color + '15' }}
          >
            {health_score >= 80 ? (
              <ShieldCheck className="w-10 h-10" style={{ color: status_color }} />
            ) : health_score >= 50 ? (
              <AlertTriangle className="w-10 h-10" style={{ color: status_color }} />
            ) : (
              <ShieldAlert className="w-10 h-10" style={{ color: status_color }} />
            )}
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <span 
                className="px-3 py-1 text-xs font-bold uppercase rounded-full tracking-wider text-white"
                style={{ backgroundColor: status_color }}
              >
                {status}
              </span>
              <span className="text-xs font-mono text-slate-400">Host: {host_info.hostname}</span>
            </div>
            <h2 className="text-2xl font-black text-white mt-1.5">Host System Self-Assessment</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              OS: <strong className="text-slate-300">{host_info.os}</strong> ({host_info.architecture})
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-center bg-slate-950 p-4 rounded-xl border border-slate-800">
            <div className="text-4xl font-black font-mono" style={{ color: status_color }}>
              {health_score}<span className="text-sm text-slate-500">/100</span>
            </div>
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-0.5">
              System Health Score
            </div>
          </div>

          <button
            onClick={onRescan}
            className="px-4 py-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl transition flex items-center gap-2 shadow-lg shadow-cyan-500/20"
          >
            <RefreshCw className="w-4 h-4" /> Re-scan Host
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div 
          onClick={() => setActiveSubTab('processes')}
          className="bg-slate-900/80 border border-slate-800 hover:border-cyan-500/50 p-4 rounded-xl cursor-pointer transition"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
            <span>Running Processes</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-300 mt-2">
            {summary.total_processes_scanned}
          </div>
          <div className="text-xs mt-1">
            {summary.suspicious_processes > 0 ? (
              <span className="text-rose-400 font-bold">{summary.suspicious_processes} Suspicious Anomaly Detected</span>
            ) : (
              <span className="text-emerald-400 font-bold">All Monitored Processes Verified</span>
            )}
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('vulns')}
          className="bg-slate-900/80 border border-slate-800 hover:border-amber-500/50 p-4 rounded-xl cursor-pointer transition"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
            <span>Known CVEs Found</span>
            <AlertOctagon className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
            {summary.known_vulnerabilities_detected}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Across {summary.installed_software_scanned} audited packages
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('forecast')}
          className="bg-slate-900/80 border border-slate-800 hover:border-purple-500/50 p-4 rounded-xl cursor-pointer transition"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
            <span>Forecasted Vectors</span>
            <TrendingUp className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-2">
            {threat_forecast.length} Scenarios
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Predictive threat vectors modeled
          </div>
        </div>

        <div 
          onClick={() => setActiveSubTab('remediation')}
          className="bg-slate-900/80 border border-slate-800 hover:border-emerald-500/50 p-4 rounded-xl cursor-pointer transition"
        >
          <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
            <span>Required Fixes</span>
            <Wrench className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-2">
            {remediation_plan.length} Actions
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Prioritized remediation steps
          </div>
        </div>
      </div>

      {/* Sub-Navigation Buttons */}
      <div className="flex flex-wrap gap-2 bg-slate-900/60 p-1.5 rounded-xl border border-slate-800 text-xs font-bold">
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
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg transition ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 font-black shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
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
          {/* Active Alerts Banner if threats exist */}
          {active_threats.length > 0 && (
            <div className="bg-rose-950/40 border border-rose-500/60 p-5 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-rose-300 font-bold text-sm">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span>ALERT: Suspicious Malware Process Signatures Operating on Host!</span>
              </div>
              <div className="space-y-2">
                {active_threats.map((t, idx) => (
                  <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-rose-900/60 text-xs font-mono flex justify-between items-center">
                    <div>
                      <span className="text-rose-400 font-bold">{t.name} (PID: {t.pid})</span>
                      <div className="text-slate-400 mt-0.5">{t.path}</div>
                      <div className="text-amber-400 mt-0.5">{t.anomaly_reason}</div>
                    </div>
                    <span className="px-2.5 py-1 bg-rose-900 text-rose-200 text-[10px] font-bold rounded">
                      CRITICAL RISK
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Software Vulnerabilities Highlight */}
          <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
              <Package className="w-4 h-4 text-amber-400" /> Software Vulnerability &amp; Outdated Package Summary
            </h3>
            {software_audit.vulnerabilities.length === 0 ? (
              <div className="bg-slate-950 p-4 rounded-lg text-emerald-400 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> No known high-severity software CVEs identified on this machine.
              </div>
            ) : (
              <div className="space-y-2.5">
                {software_audit.vulnerabilities.map((v, idx) => (
                  <div key={idx} className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">{v.software}</span>
                        <span className="px-2 py-0.5 bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold rounded">
                          {v.cve}
                        </span>
                        <span className="px-2 py-0.5 bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold rounded">
                          CVSS {v.cvss} ({v.severity})
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1">{v.description}</p>
                      <p className="text-xs text-cyan-400 font-semibold mt-1">Recommended Action: {v.remediation}</p>
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
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
                <Package className="w-4 h-4 text-amber-400" /> Audited Installed System Packages
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Cross-referenced against NIST NVD and Known Exploited Vulnerabilities catalog.
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 font-bold">
              {software_audit.total_software_found} Software Packages Scanned
            </span>
          </div>

          <div className="overflow-x-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">Application Name</th>
                  <th className="p-3">Installed Version</th>
                  <th className="p-3">Publisher</th>
                  <th className="p-3">CVE Status</th>
                  <th className="p-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                {software_audit.installed_software.map((app, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="p-3 font-bold text-slate-200">{app.name}</td>
                    <td className="p-3 text-cyan-300">{app.version}</td>
                    <td className="p-3 text-slate-400">{app.publisher}</td>
                    <td className="p-3">
                      {app.has_cve ? (
                        <span className="text-rose-400 font-bold">{app.cve_id}</span>
                      ) : (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Up to Date
                        </span>
                      )}
                    </td>
                    <td className="p-3">
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
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" /> Monitored Host Processes
          </h3>
          <div className="overflow-x-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">PID</th>
                  <th className="p-3">Process Name</th>
                  <th className="p-3">Binary Path</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Anomaly Assessment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                {active_threats.length > 0 && active_threats.map((p, idx) => (
                  <tr key={`sus-${idx}`} className="bg-rose-950/30 hover:bg-rose-950/40">
                    <td className="p-3 text-rose-300 font-bold">{p.pid}</td>
                    <td className="p-3 text-rose-200 font-bold">{p.name}</td>
                    <td className="p-3 text-slate-300 break-all">{p.path}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 bg-rose-900 text-rose-100 text-[10px] font-bold rounded">
                        SUSPICIOUS
                      </span>
                    </td>
                    <td className="p-3 text-rose-300">{p.anomaly_reason}</td>
                  </tr>
                ))}
                {assessment.active_threats.length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-emerald-400">
                      All active process binaries verified against known OS signatures.
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
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
          <div>
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-purple-400" /> Predictive Threat &amp; Attack Surface Forecast
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Forecasts likely adversary techniques targeting this machine's specific configuration and software versions.
            </p>
          </div>

          <div className="space-y-3">
            {threat_forecast.map((fc, idx) => (
              <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between items-center">
                  <div className="font-bold text-white text-sm flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: fc.probability === 'CRITICAL' ? '#ef4444' : fc.probability === 'HIGH' ? '#f59e0b' : '#22c55e' }} />
                    {fc.vector}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400">PROBABILITY:</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                      fc.probability === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                      fc.probability === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {fc.probability}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300">{fc.reasoning}</p>

                <div className="bg-slate-900 p-2.5 rounded border border-slate-800/80 text-xs font-mono text-cyan-300">
                  <strong className="text-slate-400">Preemptive Defense:</strong> {fc.mitigation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Viewport: Remediation Plan */}
      {activeSubTab === 'remediation' && (
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl space-y-4">
          <div>
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
              <Wrench className="w-4 h-4 text-emerald-400" /> Actionable Vulnerability Remediation Plan
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Step-by-step instructions to harden this host against detected vulnerabilities and active risks.
            </p>
          </div>

          <div className="space-y-3">
            {remediation_plan.length === 0 ? (
              <div className="p-6 bg-slate-950 rounded-lg text-center text-emerald-400 text-xs">
                🎉 No immediate remediation required! System is currently in a hardened state.
              </div>
            ) : (
              remediation_plan.map((item, idx) => (
                <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex justify-between items-start gap-4">
                  <div className="space-y-1">
                    <div className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-slate-800 text-cyan-400 text-xs flex items-center justify-center font-mono font-bold">
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
      )}
    </div>
  );
};
