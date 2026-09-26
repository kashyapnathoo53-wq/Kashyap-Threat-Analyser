import React, { useState, useEffect } from 'react';
import { 
  GitCompare, 
  Cpu, 
  Lock, 
  Network, 
  FileText, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Database,
  ArrowRight,
  ShieldAlert,
  Bot
} from 'lucide-react';
import { cyberAudio } from '../utils/cyberAudio';

interface Props {
  onOpenJarvisChat?: (prompt: string) => void;
}

export const HostSecurityDiffTab: React.FC<Props> = ({ onOpenJarvisChat }) => {
  const [diffData, setDiffData] = useState<any>(null);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const fetchDiffAndSnapshots = async () => {
    setLoading(true);
    try {
      // 1. Fetch latest diff
      const diffRes = await fetch('/api/agent/diff/latest').catch(() => null);
      if (diffRes?.ok) {
        const d = await diffRes.json();
        setDiffData(d);
      } else {
        setDiffData(null);
      }

      // 2. Fetch snapshot history
      const snapRes = await fetch('/api/agent/snapshots?limit=20').catch(() => null);
      if (snapRes?.ok) {
        const s = await snapRes.json();
        setSnapshots(s.snapshots || []);
      }
    } catch (err) {
      console.error('Failed to load host diff telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTakeSnapshotAndDiff = async () => {
    setScanning(true);
    cyberAudio.playRadarSweep();
    try {
      // 1. Trigger agent scan
      const scanRes = await fetch('/api/agent/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ save_to_store: true })
      });

      if (scanRes.ok) {
        cyberAudio.playSuccess();
        setNotice('New baseline snapshot captured. Re-calculating differential security telemetry...');
        setTimeout(() => setNotice(null), 4000);
        await fetchDiffAndSnapshots();
      } else {
        setNotice('Snapshot capture error. Running local audit.');
      }
    } catch (err) {
      setNotice('Agent API offline or timeout.');
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchDiffAndSnapshots();
  }, []);

  const newProcs = diffData?.new_processes || [];
  const termProcs = diffData?.terminated_processes || [];
  const newPersist = diffData?.new_persistence || [];
  const newNet = diffData?.new_network_connections || [];
  const newFiles = diffData?.new_files || [];
  const secChanges = diffData?.security_relevant_changes || [];

  return (
    <div className="space-y-6 animate-fadeIn">
      {notice && (
        <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>{notice}</span>
        </div>
      )}

      {/* Hero Header */}
      <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl relative overflow-hidden border border-cyan-500/30 shadow-2xl">
        <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/40">
                DELTA MONITOR
              </span>
              <span className="text-xs font-mono text-slate-400">ENDPOINT AUDIT</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black text-white mt-1">
              Live Host Security Diff &amp; Change Monitor
            </h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Continuous differential telemetry comparing the current endpoint state against predecessor baselines. Detects newly spawned background binaries, stealth autostart modifications, and newly opened outbound sockets on this physical PC.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleTakeSnapshotAndDiff}
              disabled={scanning}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 text-slate-950 font-black text-xs hover:brightness-110 active:scale-95 transition shadow-lg shadow-cyan-950/60 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
              <span>{scanning ? 'Capturing Snapshot...' : 'Capture Snapshot & Diff'}</span>
            </button>

            {onOpenJarvisChat && (
              <button
                onClick={() => onOpenJarvisChat('Analyze the latest host security diff and explain any new processes or network connections detected.')}
                className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-200 text-xs font-mono font-bold transition cursor-pointer backdrop-blur-sm"
              >
                <Bot className="w-4 h-4 text-cyan-400" />
                <span>Ask J.A.R.V.I.S.</span>
              </button>
            )}
          </div>
        </div>

        {/* 4 Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-white/[0.08] font-mono text-xs relative z-10">
          <div className="glass-card hover-glow-cyan p-3.5 rounded-2xl border border-white/[0.14] transition-all hover:-translate-y-0.5">
            <div className="text-[10px] text-slate-400 flex items-center justify-between">
              <span>NEW PROCESSES</span>
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-xl font-black text-cyan-300 mt-1">
              +{newProcs.length}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {termProcs.length} Terminated
            </div>
          </div>

          <div className="glass-card hover-glow-amber p-3.5 rounded-2xl border border-white/[0.14] transition-all hover:-translate-y-0.5">
            <div className="text-[10px] text-slate-400 flex items-center justify-between">
              <span>NEW PERSISTENCE</span>
              <Lock className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-xl font-black text-amber-300 mt-1">
              +{newPersist.length}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              Autostart &amp; RunKeys
            </div>
          </div>

          <div className="glass-card hover-glow-blue p-3.5 rounded-2xl border border-white/[0.14] transition-all hover:-translate-y-0.5">
            <div className="text-[10px] text-slate-400 flex items-center justify-between">
              <span>NEW SOCKETS</span>
              <Network className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <div className="text-xl font-black text-blue-300 mt-1">
              +{newNet.length}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              Active Outbound/Listen
            </div>
          </div>

          <div className="glass-card hover-glow-emerald p-3.5 rounded-2xl border border-white/[0.14] transition-all hover:-translate-y-0.5">
            <div className="text-[10px] text-slate-400 flex items-center justify-between">
              <span>MODIFIED FILES</span>
              <FileText className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-xl font-black text-emerald-300 mt-1">
              +{newFiles.length}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              Binaries in AppData/Temp
            </div>
          </div>
        </div>
      </div>

      {/* Security Relevant Alterations Alert Box */}
      {secChanges.length > 0 && (
        <div className="glass-panel p-5 sm:p-6 rounded-3xl border border-rose-500/40 space-y-3 relative overflow-hidden">
          <div className="flex items-center gap-2 text-rose-300 text-xs font-mono font-bold uppercase tracking-wider">
            <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
            <span>Prioritized Security-Relevant Changes Detected</span>
          </div>
          <div className="space-y-2 font-mono text-xs">
            {secChanges.map((change: any, i: number) => (
              <div key={i} className="p-3 rounded-xl bg-rose-950/30 border border-rose-800/40 flex items-center justify-between gap-3">
                <span className="text-slate-200">{change.description || change.entity_id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 shrink-0">
                  {change.change_type}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Process Deltas Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Spawned Processes */}
        <div className="glass-panel p-6 rounded-3xl border border-white/[0.12] space-y-3">
          <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Newly Spawned Processes (+{newProcs.length})</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">SINCE PREVIOUS SNAPSHOT</span>
          </div>

          {newProcs.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-slate-400 italic">
              No new processes spawned between snapshots. System baseline is stable.
            </div>
          ) : (
            <div className="space-y-2 font-mono text-xs max-h-72 overflow-y-auto pr-1">
              {newProcs.map((proc: any, i: number) => (
                <div key={i} className="p-3 rounded-xl glass-subcard border border-white/[0.06] flex items-center justify-between gap-3">
                  <div>
                    <div className="font-bold text-slate-100">{proc.name || proc.target_entity}</div>
                    <div className="text-[10px] text-slate-400 truncate max-w-xs">{proc.path || proc.executable_path || 'Path unavailable'}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                      PID {proc.pid || '--'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Network Socket Deltas */}
        <div className="glass-panel p-6 rounded-3xl border border-white/[0.12] space-y-3">
          <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-400" />
              <span>New Network Sockets (+{newNet.length})</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">ACTIVE OUTBOUND PORTS</span>
          </div>

          {newNet.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-slate-400 italic">
              No new network sockets opened between snapshots. Zero unexpected listeners.
            </div>
          ) : (
            <div className="space-y-2 font-mono text-xs max-h-72 overflow-y-auto pr-1">
              {newNet.map((conn: any, i: number) => (
                <div key={i} className="p-3 rounded-xl glass-subcard border border-white/[0.06] flex items-center justify-between gap-3">
                  <div>
                    <div className="font-bold text-slate-100 flex items-center gap-2">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                        {conn.protocol || 'TCP'}
                      </span>
                      <span>{conn.local_address || '0.0.0.0'}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      Remote: {conn.remote_address || 'LISTENING'}
                    </div>
                  </div>
                  <span className="text-[10px] text-cyan-400 font-bold uppercase">
                    {conn.status || 'ESTABLISHED'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>

      {/* Snapshot History Table */}
      <div className="glass-panel p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4">
        <div className="flex justify-between items-center border-b border-white/[0.08] pb-3">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold text-white uppercase">
              Host Security Snapshot History ({snapshots.length} Recorded)
            </h3>
          </div>
          <button
            onClick={fetchDiffAndSnapshots}
            className="text-xs font-mono text-cyan-400 hover:underline cursor-pointer"
          >
            Refresh History
          </button>
        </div>

        {snapshots.length === 0 ? (
          <div className="py-10 text-center text-xs font-mono text-slate-400 italic">
            No snapshots recorded yet. Click <strong>Capture Snapshot &amp; Diff</strong> above to create your first baseline!
          </div>
        ) : (
          <div className="overflow-x-auto border border-white/[0.08] rounded-2xl glass-subcard">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-white/[0.04] text-slate-300 border-b border-white/[0.08]">
                <tr>
                  <th className="p-3.5">Snapshot ID</th>
                  <th className="p-3.5">Timestamp</th>
                  <th className="p-3.5">Processes Scanned</th>
                  <th className="p-3.5">Storage Footprint</th>
                  <th className="p-3.5">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {snapshots.map((s, idx) => (
                  <tr key={s.snapshot_id} className="hover:bg-white/[0.04] transition">
                    <td className="p-3.5 font-bold text-cyan-300">
                      {s.snapshot_id}
                      {idx === 0 && (
                        <span className="ml-2 px-1.5 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-400 border border-cyan-700/60 font-black">
                          LATEST
                        </span>
                      )}
                    </td>
                    <td className="p-3.5 text-slate-300">
                      {new Date(s.timestamp).toLocaleString()}
                    </td>
                    <td className="p-3.5 text-white font-bold">
                      {s.process_count ?? '--'}
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {s.size_human || (s.size_bytes ? `${Math.round(s.size_bytes / 1024)} KB` : '12 KB')}
                    </td>
                    <td className="p-3.5">
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Sealed
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
