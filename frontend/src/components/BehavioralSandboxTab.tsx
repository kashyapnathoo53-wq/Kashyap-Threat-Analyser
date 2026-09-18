import React, { useState } from 'react';
import { BehavioralAnalysis } from '../types';
import { ProcessTreeGraph } from './ProcessTreeGraph';
import { SectionGuide } from './SectionGuide';
import { Terminal, Network, HardDrive, Filter, Activity, Cpu, Radio, ShieldAlert } from 'lucide-react';

interface Props {
  behavioral: BehavioralAnalysis;
}

export const BehavioralSandboxTab: React.FC<Props> = ({ behavioral }) => {
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredApiStream = behavioral.api_call_stream.filter(api => {
    const matchesRisk = riskFilter === 'ALL' || api.risk === riskFilter;
    const matchesQuery = api.api.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         api.arguments.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         api.process.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesRisk && matchesQuery;
  });

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="Dynamic Behavioral Sandbox &amp; Runtime Emulation"
        badge="Live Telemetry Tracer"
        whatItDoes="Simulates live execution of the sample inside a controlled sandbox environment. It traces all Win32 and NT kernel API calls (Syscalls), maps parent-to-child process creation trees, tracks modifications to the filesystem and Windows Registry RunKeys, and monitors simulated outbound network sockets (C2 beaconing, DNS requests, HTTP POST exfiltration)."
        howItHelps="Static analysis can be fooled by polymorphic encryption or packed code. Dynamic behavioral analysis reveals what the malware actually DOES when executed: what processes it spawns, what registry keys it hijacks to persist through reboots, and what servers it connects to for command-and-control instructions."
        keyIndicators={[
          { label: "vssadmin.exe delete shadows", detail: "Ransomware behavior: inhibits system recovery so victims cannot restore previous file versions", severity: "critical" },
          { label: "CreateRemoteThread / NtUnmapViewOfSection", detail: "Process hollowing and shellcode execution inside legitimate system processes like svchost.exe", severity: "critical" },
          { label: "CryptUnprotectData / Login Data", detail: "Infostealer behavior: dumping Chrome/Firefox/Edge stored passwords using Windows DPAPI", severity: "critical" },
          { label: "HKCU\\...\\CurrentVersion\\Run", detail: "Host persistence: ensuring the malware re-launches every time Windows starts up", severity: "high" },
          { label: "Outbound C2 IP Connections", detail: "Direct network beacons transmitting victim host information or downloading second-stage payloads", severity: "high" }
        ]}
        analystTip="Expand the Process Execution Hierarchy Tree below to identify hidden subprocesses. Modern loaders often launch cmd.exe or powershell.exe with base64 encoded arguments to evade basic EDR detection."
        defaultExpanded={false}
      />

      {/* Process Execution Hierarchy Tree */}
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
        <h3 className="text-base font-bold text-slate-200 mb-1 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" /> Interactive Execution Process Tree
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Hierarchical parent-child process execution tree simulated in isolation sandbox.
        </p>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 max-h-80 overflow-y-auto">
          <ProcessTreeGraph node={behavioral.process_tree} />
        </div>
      </div>

      {/* API Call Stream Trace Viewer */}
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
          <div>
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" /> Dynamic OS API Trace Log ({behavioral.total_api_calls})
            </h3>
            <p className="text-xs text-slate-400">
              Interception log of Win32/NT Syscall invocations during binary emulation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search API or args..."
              className="bg-slate-950 border border-slate-800 text-xs rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 w-full sm:w-48"
            />

            <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(risk => (
                <button
                  key={risk}
                  onClick={() => setRiskFilter(risk)}
                  className={`px-2.5 py-1 rounded font-semibold ${
                    riskFilter === risk 
                      ? risk === 'CRITICAL' ? 'bg-rose-500 text-white' : risk === 'HIGH' ? 'bg-amber-500 text-slate-950' : 'bg-cyan-500 text-slate-950'
                      : 'text-slate-400'
                  }`}
                >
                  {risk}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-2.5">Time</th>
                <th className="p-2.5">Process</th>
                <th className="p-2.5">API Function</th>
                <th className="p-2.5">Category</th>
                <th className="p-2.5">Arguments / Call Context</th>
                <th className="p-2.5">Return</th>
                <th className="p-2.5">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
              {filteredApiStream.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-4 text-center text-slate-500 italic">No API calls match filter.</td>
                </tr>
              ) : (
                filteredApiStream.map((api, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="p-2.5 text-slate-500">{api.timestamp.toFixed(1)}s</td>
                    <td className="p-2.5 text-cyan-300 font-bold">{api.process}</td>
                    <td className="p-2.5 text-amber-300 font-bold">{api.api}</td>
                    <td className="p-2.5 text-slate-400">{api.category}</td>
                    <td className="p-2.5 text-slate-300 max-w-xs truncate" title={api.arguments}>{api.arguments}</td>
                    <td className="p-2.5 text-slate-400">{api.return_val}</td>
                    <td className="p-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        api.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        api.risk === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {api.risk}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Filesystem/Registry Mutations & Network Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
          <h3 className="text-base font-bold text-slate-200 mb-3 flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-emerald-400" /> Filesystem & Registry Activity
          </h3>
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1 text-xs font-mono">
            {behavioral.filesystem_activity.map((fs, idx) => (
              <div key={`fs-${idx}`} className="bg-slate-950/70 p-2 rounded border border-slate-800 flex justify-between items-center">
                <span className="text-emerald-400 font-bold mr-2">[{fs.action}]</span>
                <span className="text-slate-300 truncate flex-1">{fs.path}</span>
                <span className="text-slate-500 ml-2">{fs.size}</span>
              </div>
            ))}
            {behavioral.registry_activity.map((reg, idx) => (
              <div key={`reg-${idx}`} className="bg-slate-950/70 p-2 rounded border border-slate-800 flex justify-between items-center">
                <span className="text-purple-400 font-bold mr-2">[{reg.action}]</span>
                <span className="text-slate-300 truncate flex-1">{reg.key}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
          <h3 className="text-base font-bold text-slate-200 mb-3 flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" /> Dynamic Network Traffic Capture
          </h3>
          <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1 text-xs">
            {behavioral.network_activity.map((net, idx) => (
              <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="flex justify-between items-center mb-1">
                  <span className="px-2 py-0.5 bg-cyan-950 text-cyan-300 font-mono font-bold rounded border border-cyan-800">
                    {net.proto} &rarr; {net.destination}
                  </span>
                  <span className="text-slate-400 font-mono">{net.bytes_sent} Bytes</span>
                </div>
                <div className="text-slate-300 font-mono text-[11px] truncate">
                  Domain: <strong className="text-cyan-400">{net.domain}</strong>
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5">
                  Type: {net.type}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
