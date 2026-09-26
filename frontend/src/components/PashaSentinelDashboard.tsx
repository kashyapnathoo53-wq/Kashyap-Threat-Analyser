import React, { useState, useEffect } from 'react';
import { 
  AgentStatus, 
  SuspiciousCandidate, 
  CandidateQueueSummary, 
  SecuritySnapshotSummary,
  AttackStory,
  SecurityTimeline,
  BlastRadiusReport,
  EvidencePackageSummary,
  RemediationHistoryItem
} from '../types';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, RefreshCw, Zap, Terminal, 
  Layers, Clock, Crosshair, Box, CheckCircle2, AlertOctagon, 
  Lock, ArrowRight, Play, Archive, Database, Activity, ExternalLink
} from 'lucide-react';
import { cyberAudio } from '../utils/cyberAudio';

const API_BASE = 'http://127.0.0.1:8000';

interface Props {
  onOpenJarvisChat?: (promptText?: string) => void;
}

export const PashaSentinelDashboard: React.FC<Props> = ({ onOpenJarvisChat }) => {
  // Navigation & Sub-views
  const [activeSubTab, setActiveSubTab] = useState<'queue' | 'story' | 'timeline' | 'blast' | 'diff' | 'remediation' | 'evidence'>('queue');
  
  // Core Telemetry State
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [queueSummary, setQueueSummary] = useState<CandidateQueueSummary | null>(null);
  const [candidates, setCandidates] = useState<SuspiciousCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<SuspiciousCandidate | null>(null);
  const [snapshots, setSnapshots] = useState<SecuritySnapshotSummary[]>([]);
  const [diffData, setDiffData] = useState<any>(null);

  // Investigation & Forensic State
  const [attackStory, setAttackStory] = useState<AttackStory | null>(null);
  const [timeline, setTimeline] = useState<SecurityTimeline | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [evidencePackages, setEvidencePackages] = useState<EvidencePackageSummary[]>([]);
  const [remediationHistory, setRemediationHistory] = useState<RemediationHistoryItem[]>([]);

  // Action Loading States
  const [loading, setLoading] = useState<boolean>(false);
  const [scanningHost, setScanningHost] = useState<boolean>(false);
  const [investigating, setInvestigating] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Remediation Execution States
  const [remedAction, setRemedAction] = useState<'TERMINATE_PROCESS' | 'QUARANTINE_FILE' | 'ISOLATE_NETWORK'>('TERMINATE_PROCESS');
  const [remedTarget, setRemedTarget] = useState<string>('');
  const [dryRunToken, setDryRunToken] = useState<string | null>(null);
  const [confirmInput, setConfirmInput] = useState<string>('');

  // Initial Load
  useEffect(() => {
    fetchInitialTelemetry();
  }, []);

  const showFeedback = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const fetchInitialTelemetry = async () => {
    setLoading(true);
    try {
      // 1. Agent Status
      const statusRes = await fetch(`${API_BASE}/api/agent/status`).catch(() => null);
      if (statusRes?.ok) {
        setAgentStatus(await statusRes.json());
      }

      // 2. Candidate Queue Summary & List
      const sumRes = await fetch(`${API_BASE}/api/agent/candidates/summary`).catch(() => null);
      if (sumRes?.ok) {
        setQueueSummary(await sumRes.json());
      }

      const listRes = await fetch(`${API_BASE}/api/agent/candidates?limit=20`).catch(() => null);
      if (listRes?.ok) {
        const data = await listRes.json();
        setCandidates(data.candidates || []);
        if (data.candidates?.length > 0 && !selectedCandidate) {
          setSelectedCandidate(data.candidates[0]);
        }
      }

      // 3. Snapshots
      const snapRes = await fetch(`${API_BASE}/api/agent/snapshots?limit=5`).catch(() => null);
      if (snapRes?.ok) {
        const snapData = await snapRes.json();
        setSnapshots(snapData.snapshots || []);
      }

      // 4. Latest Diff
      const diffRes = await fetch(`${API_BASE}/api/agent/diff/latest`).catch(() => null);
      if (diffRes?.ok) {
        setDiffData(await diffRes.json());
      }

      // 5. Evidence Packages
      const pkgRes = await fetch(`${API_BASE}/api/agent/evidence/packages`).catch(() => null);
      if (pkgRes?.ok) {
        const pkgData = await pkgRes.json();
        setEvidencePackages(Array.isArray(pkgData) ? pkgData : (pkgData.packages || []));
      }

      // 6. Remediation Quarantined Records
      const quarRes = await fetch(`${API_BASE}/api/agent/remediation/quarantine`).catch(() => null);
      if (quarRes?.ok) {
        const quarData = await quarRes.json();
        setRemediationHistory(Array.isArray(quarData) ? quarData : (quarData.records || []));
      }

      // 7. Load Latest Attack Story & Timeline
      loadLatestForensics();
    } catch (err) {
      console.error('Error fetching telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadLatestForensics = async (candidateId?: string) => {
    try {
      const storyUrl = candidateId 
        ? `${API_BASE}/api/agent/attack-story/${candidateId}`
        : `${API_BASE}/api/agent/attack-story/latest`;
      const sRes = await fetch(storyUrl).catch(() => null);
      if (sRes?.ok) setAttackStory(await sRes.json());

      const timeUrl = candidateId
        ? `${API_BASE}/api/agent/timeline/${candidateId}`
        : `${API_BASE}/api/agent/timeline/latest`;
      const tRes = await fetch(timeUrl).catch(() => null);
      if (tRes?.ok) setTimeline(await tRes.json());

      const bRes = await fetch(`${API_BASE}/api/agent/blast-radius/latest`).catch(() => null);
      if (bRes?.ok) setBlastRadius(await bRes.json());
    } catch (e) {
      console.warn('Forensics load error:', e);
    }
  };

  const handleScanHost = async () => {
    cyberAudio.playClick();
    setScanningHost(true);
    showFeedback('Executing read-only Windows security telemetry scan...');

    try {
      const scanRes = await fetch(`${API_BASE}/api/agent/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ save_to_store: true })
      });

      if (!scanRes.ok) throw new Error('Host scan failed');

      // Auto-detect candidates from snapshot and diff
      await fetch(`${API_BASE}/api/agent/candidates/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_queue: true })
      });

      showFeedback('Snapshot captured! New candidate threats enqueued.');
      await fetchInitialTelemetry();
    } catch (err) {
      showFeedback('Scan failed. Is Pasha backend running?');
    } finally {
      setScanningHost(false);
    }
  };

  const handleInvestigateNext = async () => {
    cyberAudio.playClick();
    setInvestigating(true);
    showFeedback('Dispatching autonomous sandbox investigation...');

    try {
      const res = await fetch(`${API_BASE}/api/agent/investigate/next`, { method: 'POST' });
      if (res.status === 404) {
        showFeedback('No pending candidates in queue.');
      } else if (res.ok) {
        const data = await res.json();
        showFeedback(`Analyzed candidate: ${data.candidate_id}`);
        await fetchInitialTelemetry();
        loadLatestForensics(data.candidate_id);
      }
    } catch (e) {
      showFeedback('Investigation execution error.');
    } finally {
      setInvestigating(false);
    }
  };

  const handleInvestigateCandidate = async (candId: string) => {
    cyberAudio.playClick();
    setInvestigating(true);
    showFeedback(`Investigating candidate ${candId}...`);
    try {
      const res = await fetch(`${API_BASE}/api/agent/investigate/${candId}`, { method: 'POST' });
      if (res.ok) {
        showFeedback(`Investigation complete for ${candId}!`);
        await fetchInitialTelemetry();
        loadLatestForensics(candId);
        setActiveSubTab('story');
      }
    } catch (e) {
      showFeedback('Investigation failed.');
    } finally {
      setInvestigating(false);
    }
  };

  const handleDryRunRemediation = async () => {
    if (!remedTarget) {
      showFeedback('Please provide a target process PID or file path.');
      return;
    }
    cyberAudio.playClick();
    try {
      const res = await fetch(`${API_BASE}/api/agent/remediation/dry-run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: remedAction,
          target_entity: remedTarget,
          reason: 'Admin requested containment'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.is_safe) {
          setDryRunToken(data.confirmation_token);
          setConfirmInput(data.confirmation_token);
          showFeedback('Dry run PASSED safety checks. Confirmation token generated.');
        } else {
          setDryRunToken(null);
          showFeedback(`BLOCKED BY GUARDRAILS: ${data.block_reason}`);
        }
      }
    } catch (e) {
      showFeedback('Dry-run request error.');
    }
  };

  const handleExecuteRemediation = async () => {
    if (!dryRunToken || confirmInput !== dryRunToken) {
      showFeedback('Invalid confirmation token. Remediation rejected.');
      return;
    }
    cyberAudio.playClick();
    try {
      const res = await fetch(`${API_BASE}/api/agent/remediation/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: remedAction,
          target_entity: remedTarget,
          reason: 'Manual containment authorized',
          user_confirmed: true,
          confirmation_token: confirmInput
        })
      });
      if (res.ok) {
        const data = await res.json();
        showFeedback(`Remediation executed! Result: ${data.details}`);
        setDryRunToken(null);
        setConfirmInput('');
        fetchInitialTelemetry();
      } else {
        const err = await res.json();
        showFeedback(`Remediation rejected: ${err.detail || 'Execution error'}`);
      }
    } catch (e) {
      showFeedback('Remediation error.');
    }
  };

  const handleCreateEvidencePackage = async (candId: string) => {
    cyberAudio.playClick();
    showFeedback('Generating immutable forensic evidence package (.zip)...');
    try {
      const res = await fetch(`${API_BASE}/api/agent/evidence/package/${candId}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        showFeedback(`Package created! SHA-256: ${data.zip_sha256?.substring(0, 16)}...`);
        fetchInitialTelemetry();
        setActiveSubTab('evidence');
      }
    } catch (e) {
      showFeedback('Evidence packaging error.');
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="fixed top-20 right-6 z-50 bg-slate-900 border border-cyan-400 text-cyan-200 px-4 py-2.5 rounded-xl shadow-2xl flex items-center gap-2 font-mono text-xs animate-slideDown">
          <Zap className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Hero Sentinel Banner */}
      <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl relative overflow-hidden border border-cyan-500/40 shadow-2xl transition-all duration-500 group">
        {/* Top specular reflection line */}
        <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/15 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/20 border border-cyan-400/50 flex items-center justify-center shadow-lg shadow-cyan-950/80 backdrop-blur-md">
                <ShieldCheck className="w-6 h-6 text-cyan-300" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black text-white tracking-wide">
                    PASHA 2.0 AUTONOMIC SENTINEL
                  </h1>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/40">
                    v{agentStatus?.agent_version || '2.0.0'}
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-300 flex items-center gap-2 mt-0.5">
                  <span className="text-cyan-400 font-bold">{agentStatus?.machine_id || 'LOCAL_WINDOWS_HOST'}</span>
                  <span>&bull;</span>
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse" />
                    SOVEREIGN READ-ONLY DEFENSE
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Action Center */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleScanHost}
              disabled={scanningHost}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 text-slate-950 font-black text-xs hover:brightness-110 active:scale-95 transition shadow-lg shadow-cyan-950/60 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${scanningHost ? 'animate-spin' : ''}`} />
              <span>{scanningHost ? 'Scanning Host...' : 'Scan Host Telemetry'}</span>
            </button>

            <button
              onClick={handleInvestigateNext}
              disabled={investigating}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-purple-950/60 hover:bg-purple-900/80 border border-purple-500/50 text-purple-200 font-bold text-xs active:scale-95 transition cursor-pointer shadow-md disabled:opacity-50 backdrop-blur-sm"
            >
              <Play className="w-4 h-4 text-purple-400" />
              <span>Auto-Investigate Next</span>
            </button>

            {onOpenJarvisChat && (
              <button
                onClick={() => onOpenJarvisChat('Analyze the current Pasha 2.0 candidate queue and give me a tactical assessment.')}
                className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-200 text-xs font-mono font-bold transition cursor-pointer backdrop-blur-sm"
              >
                <span>Ask J.A.R.V.I.S.</span>
              </button>
            )}
          </div>
        </div>

        {/* Telemetry Quick Counter Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-white/[0.08] font-mono text-xs relative z-10">
          <div className="glass-card hover-glow-cyan p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 relative overflow-hidden group hover:-translate-y-0.5">
            <div className="absolute top-0 inset-x-3 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
            <div className="absolute -top-8 -right-8 w-20 h-20 rounded-full bg-cyan-500/15 blur-lg pointer-events-none" />
            <div className="text-[10px] text-slate-400">THREAT QUEUE</div>
            <div className="text-lg font-black text-cyan-300 mt-0.5">
              {queueSummary?.total_candidates ?? 0}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {queueSummary?.counts_by_status?.PENDING || 0} Pending &bull; {queueSummary?.counts_by_status?.ANALYZED || 0} Analyzed
            </div>
          </div>

          <div className="glass-card hover-glow-blue p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 relative overflow-hidden group hover:-translate-y-0.5">
            <div className="absolute top-0 inset-x-3 h-[1px] bg-gradient-to-r from-transparent via-blue-400/40 to-transparent pointer-events-none" />
            <div className="absolute -top-8 -right-8 w-20 h-20 rounded-full bg-blue-500/15 blur-lg pointer-events-none" />
            <div className="text-[10px] text-slate-400">SECURITY SNAPSHOTS</div>
            <div className="text-lg font-black text-slate-100 mt-0.5">
              {agentStatus?.storage?.total_snapshots ?? 0}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              Disk: {agentStatus?.storage?.total_disk_human || '0 KB'}
            </div>
          </div>

          <div className="glass-card hover-glow-amber p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 relative overflow-hidden group hover:-translate-y-0.5">
            <div className="absolute top-0 inset-x-3 h-[1px] bg-gradient-to-r from-transparent via-amber-400/40 to-transparent pointer-events-none" />
            <div className="absolute -top-8 -right-8 w-20 h-20 rounded-full bg-amber-500/15 blur-lg pointer-events-none" />
            <div className="text-[10px] text-slate-400">AVG PRIORITY SCORE</div>
            <div className="text-lg font-black text-amber-400 mt-0.5">
              {Math.round(queueSummary?.average_priority_score ?? 0)}/100
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Dual Risk + Heuristics</div>
          </div>

          <div className="glass-card hover-glow-emerald p-3.5 rounded-2xl border border-white/[0.14] transition-all duration-300 relative overflow-hidden group hover:-translate-y-0.5">
            <div className="absolute top-0 inset-x-3 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent pointer-events-none" />
            <div className="absolute -top-8 -right-8 w-20 h-20 rounded-full bg-emerald-500/15 blur-lg pointer-events-none" />
            <div className="text-[10px] text-slate-400">PRESERVED EVIDENCE</div>
            <div className="text-lg font-black text-emerald-400 mt-0.5">
              {evidencePackages.length} Packages
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Cryptographically Sealed</div>
          </div>
        </div>
      </div>

      {/* Internal Sub-View Tabs */}
      <div className="flex flex-wrap items-center gap-2 glass-panel p-1.5 rounded-2xl border border-white/[0.14] text-xs font-mono font-bold backdrop-blur-xl shadow-lg">
        {[
          { id: 'queue', label: 'Candidate Queue', icon: Layers, badge: candidates.length },
          { id: 'story', label: 'Attack Story & Graph', icon: Activity },
          { id: 'timeline', label: 'Forensic Timeline', icon: Clock },
          { id: 'blast', label: 'Blast Radius & Impact', icon: Crosshair },
          { id: 'diff', label: 'Snapshots & Diff', icon: Database },
          { id: 'remediation', label: 'Guarded Containment', icon: Lock },
          { id: 'evidence', label: 'Evidence Vault', icon: Archive }
        ].map(tab => {
          const Icon = tab.icon;
          const isCurrent = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                cyberAudio.playClick();
                setActiveSubTab(tab.id as any);
              }}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl transition cursor-pointer ${
                isCurrent 
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50 shadow-md shadow-cyan-950/80 font-black' 
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <Icon className="w-3.5 h-3.5 text-cyan-400" />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span className="px-1.5 py-0.2 rounded-full text-[9px] bg-cyan-900 text-cyan-200">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* SUB-VIEW 1: CANDIDATE QUEUE */}
      {activeSubTab === 'queue' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span>Prioritized Suspicious Entities Queue ({candidates.length} items)</span>
            <button
              onClick={fetchInitialTelemetry}
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          {candidates.length === 0 ? (
            <div className="glass-panel p-12 rounded-3xl text-center space-y-3 border border-white/[0.12] relative overflow-hidden">
              <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent pointer-events-none" />
              <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto" />
              <div className="text-base font-bold text-slate-200">Host Baseline Clean</div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                No active threats or anomalous processes detected in the latest snapshot. Click <strong>Scan Host Telemetry</strong> to evaluate new runtime processes.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {candidates.map(cand => {
                const isSelected = selectedCandidate?.candidate_id === cand.candidate_id;
                return (
                  <div
                    key={cand.candidate_id}
                    onClick={() => setSelectedCandidate(cand)}
                    className={`glass-card hover-glow-cyan p-4 sm:p-5 rounded-2xl border transition-all duration-300 cursor-pointer relative overflow-hidden group hover:-translate-y-0.5 ${
                      isSelected 
                        ? 'border-cyan-400/80 shadow-2xl shadow-cyan-950/80 ring-1 ring-cyan-400/40' 
                        : 'border-white/[0.12] hover:border-cyan-400/50'
                    }`}
                  >
                    {/* Top specular reflection line */}
                    <div className="absolute top-0 inset-x-4 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
                    {/* Ambient backlight orb */}
                    <div className="absolute -top-8 -right-8 w-24 h-24 rounded-full bg-cyan-500/10 blur-xl group-hover:bg-cyan-500/20 transition-all pointer-events-none" />

                    <div className="flex items-start justify-between gap-3 relative z-10">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-black text-white">
                            {cand.process_name || cand.target_entity}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/50 backdrop-blur-sm">
                            {cand.category}
                          </span>
                        </div>
                        {cand.file_path && (
                          <div className="text-[11px] font-mono text-slate-300 truncate max-w-xs mt-1" title={cand.file_path}>
                            {cand.file_path}
                          </div>
                        )}
                      </div>

                      <div className="text-right shrink-0">
                        <div className="text-xs font-mono font-black text-rose-400">
                          PRIORITY {Math.round(cand.priority_score)}
                        </div>
                        <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded font-bold ${
                          cand.status === 'ANALYZED' ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/40' :
                          cand.status === 'QUEUED' ? 'bg-amber-950/80 text-amber-300 border border-amber-700/40' : 'bg-slate-800/80 text-slate-300 border border-white/10'
                        }`}>
                          {cand.status}
                        </span>
                      </div>
                    </div>

                    {/* Dual Metrics Bars */}
                    <div className="grid grid-cols-2 gap-3 mt-3 pt-3 border-t border-white/[0.08] text-[10px] font-mono relative z-10">
                      <div>
                        <div className="flex justify-between text-slate-400 mb-1">
                          <span>Risk Metric</span>
                          <span className="text-rose-400 font-bold">{cand.risk_score}/100</span>
                        </div>
                        <div className="w-full bg-white/[0.08] h-1.5 rounded-full overflow-hidden">
                          <div className="bg-rose-500 h-full rounded-full shadow-[0_0_8px_rgba(244,63,94,0.6)]" style={{ width: `${cand.risk_score}%` }} />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-slate-400 mb-1">
                          <span>Confidence</span>
                          <span className="text-cyan-400 font-bold">{cand.confidence_score}%</span>
                        </div>
                        <div className="w-full bg-white/[0.08] h-1.5 rounded-full overflow-hidden">
                          <div className="bg-cyan-400 h-full rounded-full shadow-[0_0_8px_rgba(6,182,212,0.6)]" style={{ width: `${cand.confidence_score}%` }} />
                        </div>
                      </div>
                    </div>

                    {/* Heuristics Matched Chips */}
                    {cand.heuristics_matched && cand.heuristics_matched.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2.5 relative z-10">
                        {cand.heuristics_matched.slice(0, 3).map((h, i) => (
                          <span key={i} className="text-[9px] font-mono glass-subcard text-slate-300 px-2 py-0.5 rounded">
                            {h}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex items-center justify-end gap-2 mt-3 pt-2 border-t border-white/[0.06] relative z-10">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInvestigateCandidate(cand.candidate_id);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-600/60 text-cyan-200 text-[10px] font-mono font-bold transition cursor-pointer backdrop-blur-sm shadow-sm"
                      >
                        Investigate
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCreateEvidencePackage(cand.candidate_id);
                        }}
                        className="px-2.5 py-1 rounded-lg glass-subcard hover:border-white/30 text-slate-300 text-[10px] font-mono transition cursor-pointer"
                      >
                        Preserve
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCandidate(cand);
                          loadLatestForensics(cand.candidate_id);
                          setActiveSubTab('story');
                        }}
                        className="px-2.5 py-1 rounded-lg glass-subcard hover:border-cyan-400/40 text-slate-300 text-[10px] font-mono transition cursor-pointer flex items-center gap-1"
                      >
                        <span>Story</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* SUB-VIEW 2: CORRELATED ATTACK STORY & GRAPH */}
      {activeSubTab === 'story' && (
        <div className="space-y-6">
          {attackStory ? (
            <>
              {/* Narrative Summary Card */}
              <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-cyan-500/30 space-y-4 relative overflow-hidden group">
                {/* Top specular reflection line */}
                <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
                <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] pb-3 relative z-10">
                  <div>
                    <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider">
                      Attack Story &bull; {attackStory.candidate_id}
                    </span>
                    <h2 className="text-lg font-black text-white mt-0.5">{attackStory.title}</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-3 py-1 rounded-full text-xs font-mono font-black bg-rose-950/80 text-rose-300 border border-rose-800/60 shadow-sm">
                      {attackStory.risk_assessment?.verdict || 'MALICIOUS'}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-200 leading-relaxed font-sans glass-subcard p-4 rounded-xl border border-white/[0.08] relative z-10">
                  {attackStory.executive_summary}
                </div>

                {/* Narrative Steps */}
                {attackStory.attack_narrative && attackStory.attack_narrative.length > 0 && (
                  <div className="space-y-2 relative z-10">
                    <span className="text-[11px] font-mono font-bold text-slate-400 uppercase">Step-by-Step Attack Progression</span>
                    <div className="space-y-2">
                      {attackStory.attack_narrative.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-3 text-xs text-slate-200 font-mono glass-subcard p-3 rounded-xl border border-white/[0.06] hover:border-cyan-400/40 transition">
                          <span className="text-cyan-400 font-black shrink-0">{idx + 1}.</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Evidence Graph Visual representation */}
              <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4 relative overflow-hidden group">
                <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
                <div className="flex justify-between items-center relative z-10">
                  <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                    Forensic Evidence Graph ({attackStory.nodes?.length || 0} Entities, {attackStory.edges?.length || 0} Relationships)
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">INTERACTIVE GRAPH TOPOLOGY</span>
                </div>

                {/* Node Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 relative z-10">
                  {attackStory.nodes?.map(node => (
                    <div key={node.id} className="glass-subcard p-3.5 rounded-xl border border-white/[0.08] space-y-1 hover:-translate-y-0.5 hover:border-cyan-400/40 transition-all duration-300">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-300 font-bold border border-white/[0.08]">
                          {node.type}
                        </span>
                        <span className={`text-[9px] font-mono font-bold ${
                          node.severity === 'CRITICAL' ? 'text-rose-400' :
                          node.severity === 'HIGH' ? 'text-amber-400' : 'text-cyan-400'
                        }`}>
                          {node.severity}
                        </span>
                      </div>
                      <div className="text-xs font-mono font-bold text-white truncate" title={node.label}>
                        {node.label}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Edges List */}
                {attackStory.edges && attackStory.edges.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-white/[0.08] space-y-2 relative z-10">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">Causal Links &amp; Vectors</span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {attackStory.edges.map((edge, i) => (
                        <div key={i} className="text-[11px] font-mono glass-subcard p-2.5 rounded-xl flex items-center justify-between text-slate-300 border border-white/[0.06]">
                          <span className="truncate max-w-[120px] text-cyan-300 font-semibold">{edge.source}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 font-bold uppercase">{edge.relation}</span>
                          <span className="truncate max-w-[120px] text-rose-300 font-semibold">{edge.target}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="glass-panel p-12 rounded-3xl text-center space-y-3 border border-white/[0.12] relative overflow-hidden">
              <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
              <Activity className="w-10 h-10 text-cyan-400 mx-auto" />
              <div className="text-sm font-bold text-white">No Attack Story Generated Yet</div>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Investigate a candidate threat from the queue to construct a correlated attack story and evidence graph.
              </p>
            </div>
          )}
        </div>
      )}

      {/* SUB-VIEW 3: FORENSIC TIMELINE */}
      {activeSubTab === 'timeline' && (
        <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4 relative overflow-hidden group">
          <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          <div className="flex justify-between items-center border-b border-white/[0.08] pb-3 relative z-10">
            <span className="text-xs font-mono font-bold text-slate-300 uppercase">
              Forensic Event Stream ({timeline?.events?.length || 0} Reconstructed Events)
            </span>
            <span className="text-[10px] font-mono text-cyan-400">CHRONOLOGICAL ORDER</span>
          </div>

          {!timeline || timeline.events?.length === 0 ? (
            <div className="py-12 text-center text-slate-400 font-mono text-xs">
              No timeline events available. Scan host or investigate a candidate to populate.
            </div>
          ) : (
            <div className="relative pl-6 space-y-4 border-l border-cyan-500/30 ml-3 relative z-10">
              {timeline.events.map((evt, idx) => (
                <div key={idx} className="relative group/event">
                  <div className="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full bg-cyan-400 border-2 border-slate-950 group-hover/event:scale-125 shadow-[0_0_10px_rgba(6,182,212,0.8)] transition" />
                  <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:border-cyan-400/50 transition-all duration-300">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300">
                          {evt.category}
                        </span>
                        <span className="text-xs font-mono font-bold text-white">{evt.action}</span>
                      </div>
                      <span className={`text-[9px] font-mono font-bold ${
                        evt.severity === 'CRITICAL' ? 'text-rose-400' :
                        evt.severity === 'HIGH' ? 'text-amber-400' : 'text-slate-400'
                      }`}>
                        {evt.severity}
                      </span>
                    </div>
                    <div className="text-xs text-slate-200 mt-1.5 font-mono">{evt.description}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-1">
                      Source: {evt.source} &bull; Target: {evt.target} &bull; {new Date(evt.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUB-VIEW 4: BLAST RADIUS & IMPACT */}
      {activeSubTab === 'blast' && (
        <div className="space-y-6">
          {blastRadius ? (
            <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-cyan-500/30 space-y-5 relative overflow-hidden group">
              <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />
              <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] pb-3 relative z-10">
                <div>
                  <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase">Impact Assessment</span>
                  <h3 className="text-lg font-black text-white">{blastRadius.target_entity}</h3>
                </div>
                <div className="text-right">
                  <div className="text-xs font-mono text-slate-400">SCOPE LEVEL</div>
                  <span className="text-sm font-mono font-black text-amber-400">{blastRadius.scope_level}</span>
                </div>
              </div>

              {/* Grid of affected surfaces */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs relative z-10">
                <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                  <div className="text-[10px] text-slate-400">AFFECTED PROCESSES</div>
                  <div className="text-lg font-black text-white mt-1">{blastRadius.affected_processes?.length || 0}</div>
                </div>

                <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                  <div className="text-[10px] text-slate-400">PERSISTENCE KEYS</div>
                  <div className="text-lg font-black text-rose-300 mt-1">{blastRadius.affected_registry_keys?.length || 0}</div>
                </div>

                <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                  <div className="text-[10px] text-slate-400">NETWORK ENDPOINTS</div>
                  <div className="text-lg font-black text-cyan-300 mt-1">{blastRadius.affected_network_endpoints?.length || 0}</div>
                </div>

                <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                  <div className="text-[10px] text-slate-400">EXPOSED FILES</div>
                  <div className="text-lg font-black text-slate-200 mt-1">{blastRadius.affected_files?.length || 0}</div>
                </div>
              </div>

              {/* Containment Recommendations */}
              {blastRadius.containment_recommendations && blastRadius.containment_recommendations.length > 0 && (
                <div className="space-y-2 mt-4 pt-3 border-t border-white/[0.08] relative z-10">
                  <span className="text-[11px] font-mono font-bold text-slate-400 uppercase">Recommended Containment Actions</span>
                  <div className="space-y-2">
                    {blastRadius.containment_recommendations.map((rec, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs font-mono text-emerald-300 glass-subcard p-3 rounded-xl border border-emerald-500/30">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="glass-panel p-12 rounded-3xl text-center space-y-3 border border-white/[0.12] relative overflow-hidden">
              <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
              <Crosshair className="w-10 h-10 text-cyan-400 mx-auto" />
              <div className="text-sm font-bold text-white">No Blast Radius Computed</div>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Scan host and evaluate candidates to analyze lateral impact and affected boundaries.
              </p>
            </div>
          )}
        </div>
      )}

      {/* SUB-VIEW 5: SNAPSHOTS & DIFF INSPECTOR */}
      {activeSubTab === 'diff' && (
        <div className="space-y-6">
          <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4 relative overflow-hidden group">
            <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
            <div className="flex justify-between items-center border-b border-white/[0.08] pb-3 relative z-10">
              <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                Latest Security Diff (Predecessor vs. Target Snapshot)
              </span>
              <button
                onClick={fetchInitialTelemetry}
                className="text-xs font-mono text-cyan-400 hover:underline cursor-pointer"
              >
                Re-calculate Diff
              </button>
            </div>

            {diffData ? (
              <div className="space-y-4 font-mono text-xs relative z-10">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                    <div className="text-[10px] text-slate-400">NEW PROCESSES</div>
                    <div className="text-lg font-black text-cyan-300 mt-0.5">
                      {diffData.new_processes?.length || 0}
                    </div>
                  </div>
                  <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                    <div className="text-[10px] text-slate-400">NEW PERSISTENCE</div>
                    <div className="text-lg font-black text-rose-300 mt-0.5">
                      {diffData.new_persistence?.length || 0}
                    </div>
                  </div>
                  <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                    <div className="text-[10px] text-slate-400">ACTIVE CONNECTIONS</div>
                    <div className="text-lg font-black text-amber-300 mt-0.5">
                      {diffData.new_network_connections?.length || 0}
                    </div>
                  </div>
                  <div className="glass-subcard p-4 rounded-2xl border border-white/[0.08] hover:-translate-y-0.5 transition-all">
                    <div className="text-[10px] text-slate-400">NEW FILES</div>
                    <div className="text-lg font-black text-slate-200 mt-0.5">
                      {diffData.new_files?.length || 0}
                    </div>
                  </div>
                </div>

                {/* Security Relevant Changes */}
                {diffData.security_relevant_changes && diffData.security_relevant_changes.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-white/[0.08] space-y-2">
                    <span className="text-[10px] font-bold text-slate-400 uppercase">Security Relevant Changes</span>
                    <div className="space-y-1.5">
                      {diffData.security_relevant_changes.map((item: any, i: number) => (
                        <div key={i} className="flex items-center justify-between p-2.5 rounded-xl glass-subcard text-[11px] border border-white/[0.06]">
                          <span className="text-slate-200 font-medium">{item.description || item.entity_id}</span>
                          <span className="text-rose-400 font-bold">{item.change_type}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-slate-400 font-mono text-xs relative z-10">
                No diff data available. Need at least 2 host snapshots to compare.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-VIEW 6: GUARDED REMEDIATION & CONTAINMENT */}
      {activeSubTab === 'remediation' && (
        <div className="space-y-6">
          {/* Whitelist Guardrail Notice */}
          <div className="glass-card hover-glow-emerald border border-emerald-500/40 p-5 rounded-2xl flex items-start gap-3 relative overflow-hidden group">
            <div className="absolute top-0 inset-x-6 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent pointer-events-none" />
            <Lock className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs font-mono text-slate-300 space-y-1 relative z-10">
              <strong className="text-emerald-400">Guarded Remediation Active:</strong>
              <p>
                Pasha 2.0 enforces strict safety guardrails. Protected Windows components (e.g. <code>csrss.exe</code>, <code>lsass.exe</code>, <code>services.exe</code>, <code>explorer.exe</code>, <code>C:\Windows\System32</code>) are permanently blacklisted from termination or quarantine. Every action requires a Dry-Run simulation and explicit confirmation token.
              </p>
            </div>
          </div>

          {/* Interactive Remediation Simulator */}
          <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4 relative overflow-hidden group">
            <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
            <h3 className="text-sm font-mono font-bold text-white uppercase relative z-10">Containment Action Simulator</h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 relative z-10">
              <div className="space-y-1.5 font-mono text-xs">
                <label className="text-slate-400">Action Type</label>
                <select
                  value={remedAction}
                  onChange={(e) => setRemedAction(e.target.value as any)}
                  className="w-full glass-input p-3 rounded-xl text-white outline-none cursor-pointer"
                >
                  <option value="TERMINATE_PROCESS">TERMINATE_PROCESS (Kill rogue PID)</option>
                  <option value="QUARANTINE_FILE">QUARANTINE_FILE (Move file to encrypted vault)</option>
                  <option value="ISOLATE_NETWORK">ISOLATE_NETWORK (Simulate network boundary)</option>
                </select>
              </div>

              <div className="space-y-1.5 font-mono text-xs">
                <label className="text-slate-400">Target Entity (PID or File Path)</label>
                <input
                  type="text"
                  placeholder="e.g. 9999 or C:\Users\AppData\evil.exe"
                  value={remedTarget}
                  onChange={(e) => setRemedTarget(e.target.value)}
                  className="w-full glass-input p-3 rounded-xl text-white outline-none"
                />
              </div>
            </div>

            <div className="flex items-center gap-3 pt-2 relative z-10">
              <button
                onClick={handleDryRunRemediation}
                className="px-4 py-2.5 bg-gradient-to-r from-cyan-600/30 via-sky-600/30 to-blue-500/30 hover:from-cyan-600/50 hover:to-blue-500/50 text-cyan-200 hover:text-white font-mono text-xs font-bold rounded-xl border border-cyan-500/50 transition cursor-pointer backdrop-blur-sm"
              >
                1. Simulate Dry Run
              </button>

              {dryRunToken && (
                <div className="flex items-center gap-2 font-mono text-xs animate-fadeIn">
                  <input
                    type="text"
                    value={confirmInput}
                    onChange={(e) => setConfirmInput(e.target.value)}
                    placeholder="Enter Token"
                    className="glass-input border-rose-500/60 p-2.5 rounded-xl text-rose-300 text-xs w-48 text-center font-bold"
                  />
                  <button
                    onClick={handleExecuteRemediation}
                    className="px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-black rounded-xl shadow-lg shadow-rose-950 transition cursor-pointer"
                  >
                    2. Confirm &amp; Execute
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Audit History Trail */}
          <div className="glass-panel p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-3 relative overflow-hidden">
            <span className="text-xs font-mono font-bold text-slate-300 uppercase relative z-10">Containment Execution History</span>
            {remediationHistory.length === 0 ? (
              <div className="py-6 text-center text-slate-400 font-mono text-xs relative z-10">
                No remediation actions executed on this host.
              </div>
            ) : (
              <div className="space-y-2 relative z-10">
                {remediationHistory.map(hist => (
                  <div key={hist.execution_id} className="p-3.5 glass-subcard rounded-xl border border-white/[0.06] flex items-center justify-between text-xs font-mono">
                    <div>
                      <span className="text-cyan-400 font-bold">{hist.action}</span>
                      <span className="text-slate-300 ml-2">&bull; {hist.target_entity}</span>
                    </div>
                    <span className="text-slate-400">{new Date(hist.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-VIEW 7: EVIDENCE VAULT */}
      {activeSubTab === 'evidence' && (
        <div className="glass-panel hover-glow-cyan p-6 sm:p-7 rounded-3xl border border-white/[0.12] space-y-4 relative overflow-hidden group">
          <div className="absolute top-0 inset-x-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          <div className="flex justify-between items-center border-b border-white/[0.08] pb-3 relative z-10">
            <span className="text-xs font-mono font-bold text-slate-300 uppercase">
              Forensic Evidence Preservation Packages ({evidencePackages.length} Sealed Bundles)
            </span>
            <span className="text-[10px] font-mono text-emerald-400 font-bold">SHA-256 VERIFIED</span>
          </div>

          {evidencePackages.length === 0 ? (
            <div className="py-12 text-center text-slate-400 font-mono text-xs relative z-10">
              No evidence packages created yet. Click <strong>Preserve</strong> on any candidate threat to seal forensic evidence.
            </div>
          ) : (
            <div className="space-y-3 relative z-10">
              {evidencePackages.map(pkg => (
                <div key={pkg.package_id} className="p-4 glass-subcard rounded-2xl border border-white/[0.08] hover:border-cyan-400/50 transition-all duration-300 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <Archive className="w-4 h-4 text-cyan-400" />
                      <span className="font-bold text-white">{pkg.package_id}.zip</span>
                      <span className="text-[10px] text-slate-400">({pkg.package_size_human})</span>
                    </div>
                    <div className="text-[11px] text-slate-300 mt-1">
                      Candidate: <strong>{pkg.candidate_id}</strong> &bull; Target: {pkg.target_entity}
                    </div>
                    <div className="text-[10px] text-cyan-300/80 truncate max-w-md mt-0.5">
                      SHA-256: {pkg.zip_sha256}
                    </div>
                  </div>

                  <a
                    href={`${API_BASE}/api/agent/evidence/download/${pkg.package_id}`}
                    download
                    className="px-3.5 py-2 rounded-xl bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-600/60 text-cyan-200 font-bold transition flex items-center justify-center gap-1.5 shrink-0 backdrop-blur-sm shadow-sm"
                  >
                    <span>Download Bundle</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
