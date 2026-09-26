import React, { useState, useEffect } from 'react';
import { 
  Shield, ShieldCheck, Laptop, Cpu, Terminal, CheckCircle2, 
  ExternalLink, Copy, Check, RefreshCw, AlertTriangle, Zap,
  Layers, Lock, Play, Download
} from 'lucide-react';
import { cyberAudio } from '../utils/cyberAudio';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onRunInstantScan: () => void;
  onRunDeepAgentScan: () => void;
  isAgentOnline: boolean;
  scanning: boolean;
}

export const LocalHostScannerModal: React.FC<Props> = ({
  isOpen,
  onClose,
  onRunInstantScan,
  onRunDeepAgentScan,
  isAgentOnline,
  scanning
}) => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [checkingAgent, setCheckingAgent] = useState<boolean>(false);
  const [agentDetected, setAgentDetected] = useState<boolean>(isAgentOnline);

  useEffect(() => {
    setAgentDetected(isAgentOnline);
  }, [isAgentOnline]);

  if (!isOpen) return null;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    cyberAudio.playClick();
    setTimeout(() => setCopiedCmd(null), 2500);
  };

  const recheckAgentStatus = async () => {
    setCheckingAgent(true);
    cyberAudio.playDataStream();
    try {
      const res = await fetch('http://127.0.0.1:8000/api/agent/status', {
        signal: AbortSignal.timeout(2500)
      }).catch(() => null);
      if (res?.ok) {
        setAgentDetected(true);
        cyberAudio.playSuccess();
      } else {
        setAgentDetected(false);
      }
    } catch {
      setAgentDetected(false);
    } finally {
      setCheckingAgent(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div 
        className="glass-panel w-full max-w-2xl rounded-3xl border border-cyan-500/30 shadow-2xl p-6 sm:p-8 relative overflow-hidden text-slate-100 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Glow Header */}
        <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-cyan-500 via-sky-400 to-blue-600" />
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 w-8 h-8 rounded-full bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition cursor-pointer"
        >
          &times;
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3.5 mb-5">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/60">
            <Shield className="w-6 h-6 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xl font-black text-white">Scan Your Computer</h3>
              <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                agentDetected 
                  ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40' 
                  : 'bg-amber-950/80 text-amber-400 border-amber-500/40'
              }`}>
                {agentDetected ? '● AGENT CONNECTED' : '○ CLOUD / STANDBY'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Secure, read-only Windows endpoint scanner for malware, hidden trojans &amp; vulnerabilities
            </p>
          </div>
        </div>

        {/* Layman Explanation Box */}
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/[0.08] mb-6 space-y-2 text-xs">
          <div className="font-bold text-slate-200 flex items-center gap-1.5">
            <Laptop className="w-4 h-4 text-cyan-400" />
            <span>How Local Scanning Works in Plain English:</span>
          </div>
          <p className="text-slate-300 leading-relaxed">
            When you visit a web page, your web browser intentionally blocks the site from opening your Windows files, checking running programs, or reading system settings for your safety.
          </p>
          <p className="text-slate-400 leading-relaxed">
            To scan your computer, Pasha uses a lightweight <strong>Local Agent</strong> on your PC (or the <strong>Chrome Extension</strong>) which reads system health locally and displays the security verdict right on this dashboard.
          </p>
        </div>

        {/* Two Clear Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          
          {/* Card 1: Deep Local PC Scan */}
          <div className={`p-5 rounded-2xl border transition relative flex flex-col justify-between ${
            agentDetected 
              ? 'bg-cyan-950/30 border-cyan-500/50 shadow-lg shadow-cyan-950/40' 
              : 'bg-slate-900/50 border-white/[0.08]'
          }`}>
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black font-mono text-cyan-400 uppercase tracking-wider">
                  Option 1: Deep PC Scan
                </span>
                {agentDetected && (
                  <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Ready
                  </span>
                )}
              </div>
              
              <h4 className="text-sm font-bold text-white">Full Windows OS Audit</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Checks all 300+ running processes, Windows autostart registry keys, scheduled tasks, and network connections for malware.
              </p>

              {agentDetected ? (
                <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-[11px] text-emerald-300 font-mono">
                  ✓ Local agent is active on this machine!
                </div>
              ) : (
                <div className="p-2.5 rounded-xl bg-slate-950 border border-white/[0.06] text-[11px] font-mono text-slate-400 space-y-1.5">
                  <div className="text-[10px] text-slate-500 uppercase">Run once in terminal:</div>
                  <div className="flex items-center justify-between bg-slate-900 px-2 py-1.5 rounded text-cyan-300 select-all overflow-x-auto">
                    <code>.\start.bat</code>
                    <button 
                      onClick={() => handleCopy('.\\start.bat', 'bat')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy command"
                    >
                      {copiedCmd === 'bat' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <div className="text-[10px] text-slate-500">Or: <code>python backend\main.py</code></div>
                </div>
              )}
            </div>

            <div className="mt-4 pt-3 border-t border-white/[0.06] flex items-center justify-between gap-2">
              <button
                onClick={() => {
                  cyberAudio.playClick();
                  onRunDeepAgentScan();
                  onClose();
                }}
                disabled={scanning}
                className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black rounded-xl text-xs transition shadow-lg shadow-cyan-950/50 cursor-pointer flex items-center justify-center gap-1.5"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Scanning PC...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>{agentDetected ? 'Start Deep Scan' : 'Try Agent Scan'}</span>
                  </>
                )}
              </button>

              {!agentDetected && (
                <button
                  onClick={recheckAgentStatus}
                  disabled={checkingAgent}
                  className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer"
                  title="Recheck Agent Connection"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${checkingAgent ? 'animate-spin text-cyan-400' : ''}`} />
                </button>
              )}
            </div>
          </div>

          {/* Card 2: Instant Browser Audit */}
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-white/[0.08] hover:border-white/20 transition flex flex-col justify-between">
            <div className="space-y-2.5">
              <span className="text-xs font-black font-mono text-emerald-400 uppercase tracking-wider">
                Option 2: Zero-Install
              </span>
              <h4 className="text-sm font-bold text-white">Browser &amp; Perimeter Audit</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Runs instantly right inside this web browser without installing anything. Audits browser sandbox integrity, memory, CPU threads, and TLS/network perimeter.
              </p>

              <div className="p-2.5 rounded-xl bg-slate-950 border border-white/[0.06] text-[11px] text-slate-300 font-mono space-y-1">
                <div>• Zero installation required</div>
                <div>• 100% private (runs locally in browser)</div>
                <div>• Instant result (&lt;0.5 seconds)</div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/[0.06]">
              <button
                onClick={() => {
                  cyberAudio.playClick();
                  onRunInstantScan();
                  onClose();
                }}
                className="w-full py-2.5 px-4 bg-slate-800 hover:bg-slate-700 text-white font-bold rounded-xl text-xs transition border border-white/[0.1] hover:border-cyan-400 cursor-pointer flex items-center justify-center gap-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Run Instant Browser Scan</span>
              </button>
            </div>
          </div>

        </div>

        {/* Chrome Extension Companion Info */}
        <div className="p-4 rounded-2xl bg-[#040d1e] border border-cyan-500/20 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-900/40 border border-cyan-500/30 flex items-center justify-center text-cyan-300 shrink-0">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <div className="font-bold text-white">Pasha Chrome Sentinel Extension</div>
              <div className="text-[11px] text-slate-400">
                Found in the <code className="text-cyan-300">/extension</code> folder. Load it in <span className="font-mono text-slate-300">chrome://extensions</span> for automatic alerts.
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-2.5 py-1 rounded-lg border border-cyan-800 shrink-0">
            MANIFEST V3 READY
          </span>
        </div>

      </div>
    </div>
  );
};
