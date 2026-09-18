import React, { useState } from 'react';
import { BehavioralAnalysis } from '../types';
import { ProcessTreeGraph } from './ProcessTreeGraph';
import { SectionGuide } from './SectionGuide';
import { Terminal, Network, HardDrive, Filter, Activity, Cpu, Radio, ShieldAlert, Globe, Key, FilePlus, Search } from 'lucide-react';

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
      <div className="glass-card p-6 rounded-3xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-lime-400" /> Interactive Virtual Process Hierarchy Tree
            </h3>
            <p className="text-xs text-slate-400">
              Parent-to-child process spawn hierarchy observed inside the execution sandbox
            </p>
          </div>
          <span className="text-[11px] font-mono text-lime-300 bg-olive-950/80 px-2.5 py-1 rounded-lg border border-lime-800/50">
            PID Root: {behavioral.process_tree.pid}
          </span>
        </div>

        <div className="bg-slate-950/90 p-4 rounded-2xl border border-white/[0.06] max-h-80 overflow-y-auto">
          <ProcessTreeGraph node={behavioral.process_tree} />
        </div>
      </div>

      {/* Syscall API Event Trace Stream */}
      <div className="glass-card p-6 rounded-3xl">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
          <div>
            <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-lime-400" /> Kernel &amp; Win32 Syscall Event Stream
            </h3>
            <p className="text-xs text-slate-400">
              Chronological API execution trace intercepted by sandbox hook engine
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-48">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search API calls..."
                className="w-full bg-slate-950 border border-lime-800/40 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-lime-400 font-mono"
              />
            </div>

            <div className="flex rounded-xl bg-slate-950 p-1 border border-white/[0.08] text-xs font-bold font-mono">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => (
                <button
                  key={level}
                  onClick={() => setRiskFilter(level)}
                  className={`px-2.5 py-1 rounded-lg transition text-[11px] ${
                    riskFilter === level ? 'bg-gradient-to-r from-lime-600 to-olive-600 text-slate-950 font-black shadow-md shadow-lime-950/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-slate-950/90 rounded-2xl border border-white/[0.06] divide-y divide-white/[0.04] max-h-80 overflow-y-auto font-mono text-xs">
          {filteredApiStream.length > 0 ? (
            filteredApiStream.map((call, idx) => (
              <div key={idx} className="p-3 hover:bg-slate-900/60 transition flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="space-y-0.5 truncate">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500">[{call.timestamp || `+${idx * 15}ms`}]</span>
                    <span className="text-white font-bold">{call.api}</span>
                    <span className="text-[10px] text-lime-300 bg-olive-950/60 px-1.5 py-0.2 rounded border border-lime-800/40">
                      PID {call.pid} ({call.process})
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate pl-4 select-all">
                    &rarr; Args: <code className="text-slate-300">{call.arguments}</code>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-500">{call.category}</span>
                  <span className={`px-2 py-0.5 text-[9px] font-black rounded uppercase ${
                    call.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    call.risk === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {call.risk}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="text-xs text-slate-500 italic text-center py-8">
              No API syscall events match the current filter.
            </div>
          )}
        </div>
      </div>

      {/* Filesystem, Registry & Network Telemetry */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Filesystem */}
        <div className="glass-card p-5 rounded-3xl">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FilePlus className="w-3.5 h-3.5 text-lime-400" /> Filesystem Drops
            </h4>
            <span className="text-[10px] font-mono text-lime-400 bg-olive-950/60 px-2 py-0.5 rounded border border-lime-800/50">
              {behavioral.filesystem_activity.length} Files
            </span>
          </div>
          <div className="space-y-2 max-h-52 overflow-y-auto pr-1 text-xs font-mono">
            {behavioral.filesystem_activity.map((f, i) => (
              <div key={i} className="p-2 bg-slate-950/80 rounded-xl border border-white/[0.04]">
                <div className="text-lime-300 font-bold truncate select-all">{f.path}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{f.action} &bull; {f.size_bytes ? `${f.size_bytes}B` : (f.size || 'Created')}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Registry */}
        <div className="glass-card p-5 rounded-3xl">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Key className="w-3.5 h-3.5 text-amber-400" /> Registry Modifications
            </h4>
            <span className="text-[10px] font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/50">
              {behavioral.registry_activity.length} Keys
            </span>
          </div>
          <div className="space-y-2 max-h-52 overflow-y-auto pr-1 text-xs font-mono">
            {behavioral.registry_activity.map((r, i) => (
              <div key={i} className="p-2 bg-slate-950/80 rounded-xl border border-white/[0.04]">
                <div className="text-amber-300 font-bold truncate select-all">{r.key}</div>
                <div className="text-[10px] text-slate-400 truncate mt-0.5">{r.value_name || r.key} = {r.data || r.value || 'Configured'}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Network C2 */}
        <div className="glass-card p-5 rounded-3xl">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-purple-400" /> Outbound C2 Sockets
            </h4>
            <span className="text-[10px] font-mono text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/50">
              {behavioral.network_activity.length} Beacons
            </span>
          </div>
          <div className="space-y-2 max-h-52 overflow-y-auto pr-1 text-xs font-mono">
            {behavioral.network_activity.map((net, i) => (
              <div key={i} className="p-2 bg-slate-950/80 rounded-xl border border-white/[0.04]">
                <div className="text-purple-300 font-bold truncate select-all">{net.destination}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{net.protocol || net.proto || 'TCP'} &bull; {net.domain || 'Direct IP'}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
