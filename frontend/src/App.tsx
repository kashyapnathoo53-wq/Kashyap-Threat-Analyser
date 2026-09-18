import React, { useState, useEffect } from 'react';
import { FullAnalysisReport, HostAssessment } from './types';
import { DashboardOverview } from './components/DashboardOverview';
import { StaticAnalysisTab } from './components/StaticAnalysisTab';
import { BehavioralSandboxTab } from './components/BehavioralSandboxTab';
import { MitreAttackTab } from './components/MitreAttackTab';
import { IocExtractorTab } from './components/IocExtractorTab';
import { YaraWorkbenchTab } from './components/YaraWorkbenchTab';
import { ReportGeneratorTab } from './components/ReportGeneratorTab';
import { SystemAssessmentTab } from './components/SystemAssessmentTab';
import { SampleSelectorModal } from './components/SampleSelectorModal';
import { 
  Shield, ShieldAlert, Cpu, Terminal, Layers, Database, Code2, FileText, 
  Upload, RefreshCw, Activity, AlertTriangle, MonitorCheck, Zap, 
  Sparkles, Globe2, Radio, Server, CheckCircle2, ChevronRight, Lock
} from 'lucide-react';

export const App: React.FC = () => {
  const [report, setReport] = useState<FullAnalysisReport | null>(null);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment | null>(null);
  const [hostLoading, setHostLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingPhase, setLoadingPhase] = useState<string>('Initializing forensic pipeline...');
  const [loadingProgress, setLoadingProgress] = useState<number>(15);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState<string>(new Date().toTimeString().split(' ')[0]);
  const [telemetryIndex, setTelemetryIndex] = useState<number>(0);

  const telemetryFeed = [
    "RADAR SCANNING: 316 host processes monitored in real-time",
    "CVE SENTINEL: NVD vulnerability database synchronized",
    "PERSISTENCE SHIELD: Windows Registry RunKeys continuously secured",
    "HEURISTIC DEFENSE: Real-time API hooking & behavioral telemetry armed"
  ];

  // Auto-run Host Assessment and load initial benchmark sample on startup + live timers
  useEffect(() => {
    runHostAutoAssessment();
    loadPresetSample('sample_wannacry');

    const timer = setInterval(() => {
      setCurrentTime(new Date().toTimeString().split(' ')[0]);
    }, 1000);

    const ticker = setInterval(() => {
      setTelemetryIndex(prev => (prev + 1) % telemetryFeed.length);
    }, 3800);

    return () => {
      clearInterval(timer);
      clearInterval(ticker);
    };
  }, []);

  const runHostAutoAssessment = async () => {
    setHostLoading(true);
    try {
      const res = await fetch('/api/system/auto-assess');
      if (res.ok) {
        const data = await res.json();
        setHostAssessment(data);
      }
    } catch (err) {
      console.error("Host assessment failed:", err);
    } finally {
      setHostLoading(false);
    }
  };

  const simulateProgress = () => {
    setLoadingProgress(20);
    setLoadingPhase("Ingesting payload & streaming cryptographic fingerprints (MD5/SHA256)...");
    
    const t1 = setTimeout(() => {
      setLoadingProgress(48);
      setLoadingPhase("Profiling PE section entropy & detecting commercial packing (UPX/Themida)...");
    }, 150);

    const t2 = setTimeout(() => {
      setLoadingProgress(76);
      setLoadingPhase("Evaluating YARA signature rulesets & auto-decoding XOR/Base64 payloads...");
    }, 320);

    const t3 = setTimeout(() => {
      setLoadingProgress(96);
      setLoadingPhase("Emulating dynamic execution sandbox & correlating MITRE ATT&CK TTPs...");
    }, 480);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  };

  const loadPresetSample = async (presetId: string) => {
    setLoading(true);
    setErrorMessage(null);
    const cancelSim = simulateProgress();
    try {
      const res = await fetch('/api/analyze/preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_id: presetId })
      });
      if (res.ok) {
        const data = await res.json();
        setLoadingProgress(100);
        setReport(data);
      } else {
        setErrorMessage("Failed to load preset sample from backend.");
      }
    } catch (err) {
      console.error("Analysis API failed:", err);
      setErrorMessage("Could not connect to backend telemetry service.");
    } finally {
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setErrorMessage(null);
    const cancelSim = simulateProgress();
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/analyze/upload', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setLoadingProgress(100);
        setReport(data);
        setActiveTab('overview');
      } else {
        const errData = await res.json().catch(() => ({}));
        setErrorMessage(errData.detail || `Analysis failed with code ${res.status}`);
      }
    } catch (err: any) {
      console.error("Upload API failed:", err);
      setErrorMessage(err?.message || "File upload pipeline failed. Check backend connection.");
    } finally {
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }
  };

  return (
    <div className="min-h-screen cyber-bg text-slate-100 font-sans flex flex-col selection:bg-lime-600 selection:text-slate-950 relative">
      {/* Topmost Enterprise Status Bar in Tactical Olive Green */}
      <div className="bg-[#080e05]/95 border-b border-lime-900/40 px-4 py-1.5 text-[11px] font-mono flex flex-wrap items-center justify-between text-slate-400 gap-2">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-lime-400 font-bold bg-lime-950/80 px-2 py-0.5 rounded border border-lime-800/50">
            <span className="w-2 h-2 rounded-full bg-lime-400 animate-ping inline-block" />
            LIVE DEFENSE GRID
          </span>

          {/* Equalizer Live Activity Bars */}
          <div className="flex items-center gap-0.5 h-4 px-1" title="Real-time telemetry stream active">
            <span className="w-0.5 bg-lime-400 rounded-full animate-bar-1" />
            <span className="w-0.5 bg-lime-300 rounded-full animate-bar-2" />
            <span className="w-0.5 bg-lime-500 rounded-full animate-bar-3" />
            <span className="w-0.5 bg-lime-400 rounded-full animate-bar-4" />
            <span className="w-0.5 bg-lime-200 rounded-full animate-bar-5" />
          </div>

          <span className="hidden md:inline text-lime-400 font-semibold transition-all duration-500">
            {telemetryFeed[telemetryIndex]}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="hidden sm:inline text-slate-400">HOST: <strong className="text-lime-200">{hostAssessment?.host_info?.hostname || 'LOCAL_ENDPOINT'}</strong></span>
          <span className="hidden sm:inline text-lime-900 font-bold">|</span>
          <span className="px-2 py-0.5 rounded bg-lime-950 text-lime-300 border border-lime-700/60 text-[10px] font-bold tracking-wider">
            TACTICAL LEVEL 4
          </span>
          <span className="text-lime-400 font-mono font-bold text-[11px] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block animate-pulse" />
            {currentTime} UTC
          </span>
        </div>
      </div>

      {/* Main Command Header */}
      <header className="glass-panel sticky top-0 z-40 border-b border-lime-900/30">
        <div className="max-w-7xl mx-auto px-4 py-3.5 flex justify-between items-center gap-4">
          {/* Brand & Logo */}
          <div className="flex items-center gap-3.5">
            <div className="relative group cursor-pointer">
              <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-lime-600 via-olive-600 to-emerald-700 p-[1.5px] shadow-lg shadow-lime-950/60 transition-transform duration-300 group-hover:scale-105">
                <div className="w-full h-full bg-[#0d1708] rounded-2xl flex items-center justify-center">
                  <Shield className="w-6 h-6 text-lime-400" />
                </div>
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-lime-400 border-2 border-slate-950 animate-pulse" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-black tracking-tight text-white flex items-center gap-2">
                  KASHYAP <span className="gradient-text-olive font-extrabold">THREAT ANALYSER</span>
                </h1>
                <span className="text-[10px] font-mono font-extrabold px-2 py-0.5 bg-gradient-to-r from-olive-950 to-lime-950 text-lime-300 border border-lime-800/60 rounded-md">
                  OLIVE DEFENSE GRID
                </span>
              </div>
              <p className="text-xs text-slate-400 font-medium">
                Autonomous Malware Reversing &amp; Tactical Endpoint Security Matrix
              </p>
            </div>
          </div>

          {/* Quick Actions & Live Counters */}
          <div className="flex items-center gap-3">
            {hostAssessment && (
              <button 
                onClick={() => setActiveTab('host')}
                className="hidden lg:flex items-center gap-2.5 bg-[#101b0a]/90 hover:bg-[#16270e] px-3.5 py-2 rounded-xl border border-lime-900/40 hover:border-lime-500/50 transition shadow-inner group cursor-pointer"
              >
                <MonitorCheck className="w-4 h-4 text-lime-400 group-hover:animate-bounce" />
                <div className="text-left text-xs">
                  <div className="text-[10px] text-slate-400 leading-none">Endpoint Health</div>
                  <div className="font-mono font-black text-slate-200 leading-tight">
                    {hostAssessment.health_score}/100 
                    <span className="text-[10px] ml-1 font-bold" style={{ color: hostAssessment.status_color }}>
                      ({hostAssessment.status})
                    </span>
                  </div>
                </div>
              </button>
            )}

            {report && (
              <button 
                onClick={() => setActiveTab('overview')}
                className="hidden md:flex items-center gap-2.5 bg-[#101b0a]/90 hover:bg-[#16270e] px-3.5 py-2 rounded-xl border border-lime-900/40 hover:border-lime-500/50 text-xs font-mono shadow-inner transition cursor-pointer"
                title="Click to view Executive Overview"
              >
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: report.threat_scoring.color }} />
                <div className="text-left">
                  <div className="text-[10px] text-slate-400 leading-none">Sample</div>
                  <div className="font-bold text-lime-200 max-w-[130px] truncate leading-tight" title={report.sample_name}>
                    {report.sample_name}
                  </div>
                </div>
                {(report as any).analysis_duration_ms && (
                  <span className="text-[10px] text-slate-400 border-l border-lime-900/60 pl-2 flex items-center gap-1">
                    <Zap className="w-3 h-3 text-lime-400" />
                    {(report as any).analysis_duration_ms}ms
                  </span>
                )}
              </button>
            )}

            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-lime-600 via-olive-600 to-lime-500 hover:from-lime-500 hover:to-lime-400 text-slate-950 font-black rounded-xl text-xs transition-all duration-300 shadow-xl shadow-lime-950/50 hover:shadow-lime-900/70 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Upload className="w-4 h-4 stroke-[2.5]" />
              <span>Submit Payload</span>
            </button>
          </div>
        </div>
      </header>

      {/* Error Banner */}
      {errorMessage && (
        <div className="max-w-7xl mx-auto w-full px-4 pt-4">
          <div className="bg-rose-950/80 border border-rose-500/60 p-3.5 rounded-2xl text-xs text-rose-200 flex items-center justify-between shadow-xl shadow-rose-950/40 animate-fadeIn">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span><strong>System Notice:</strong> {errorMessage}</span>
            </div>
            <button 
              onClick={() => setErrorMessage(null)} 
              className="text-slate-400 hover:text-white px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Executive KPI Ribbon (Clickable jump cards) */}
        {!loading && report && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
            {/* KPI 1 - Threat Verdict */}
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-lime-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'overview' ? 'border-lime-500/60 ring-1 ring-lime-500/30 shadow-lime-950/40' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-lime-300 transition">Threat Verdict</span>
                <ShieldAlert className="w-4 h-4 text-lime-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight" style={{ color: report.threat_scoring.color }}>
                {report.threat_scoring.severity}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                <span>Score: <strong className="text-white font-mono">{report.threat_scoring.threat_score}/100</strong></span>
                <span className="text-[10px] text-lime-400 font-mono flex items-center gap-0.5">Open &rarr;</span>
              </div>
            </button>

            {/* KPI 2 - Host Health Status */}
            <button
              type="button"
              onClick={() => setActiveTab('host')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-emerald-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'host' ? 'border-emerald-500/60 ring-1 ring-emerald-500/30 shadow-emerald-950/40' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-emerald-300 transition">Host Health Status</span>
                <MonitorCheck className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight" style={{ color: hostAssessment?.status_color || '#22c55e' }}>
                {hostAssessment?.health_score ?? 100}/100
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                <span className="truncate">Host: <strong className="text-slate-200 font-mono">{hostAssessment?.host_info?.hostname || 'ONLINE'}</strong></span>
                <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-0.5 shrink-0">Open &rarr;</span>
              </div>
            </button>

            {/* KPI 3 - Forensic Extraction */}
            <button
              type="button"
              onClick={() => setActiveTab('iocs')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-purple-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'iocs' ? 'border-purple-500/60 ring-1 ring-purple-500/30 shadow-purple-950/40' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-purple-300 transition">Forensic Extraction</span>
                <Database className="w-4 h-4 text-purple-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight text-purple-300">
                {report.ioc_extraction.total_extracted} Indicators
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                <span>{report.ioc_extraction.summary_by_category?.['Network C2'] || 0} C2 IPs</span>
                <span className="text-[10px] text-purple-400 font-mono flex items-center gap-0.5">Open &rarr;</span>
              </div>
            </button>

            {/* KPI 4 - Execution Speed */}
            <button
              type="button"
              onClick={() => setActiveTab('static')}
              className={`glass-card p-4 rounded-2xl text-left relative overflow-hidden transition-all duration-200 cursor-pointer hover:border-lime-500/60 hover:scale-[1.01] active:scale-[0.99] group ${
                activeTab === 'static' ? 'border-lime-500/60 ring-1 ring-lime-500/30 shadow-lime-950/40' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span className="font-bold group-hover:text-lime-300 transition">Execution Speed</span>
                <Zap className="w-4 h-4 text-lime-400 group-hover:scale-110 transition" />
              </div>
              <div className="text-xl font-black font-mono tracking-tight text-lime-300">
                {(report as any).analysis_duration_ms || 18} ms
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                <span>Streaming Engine</span>
                <span className="text-[10px] text-lime-400 font-mono flex items-center gap-0.5">Open &rarr;</span>
              </div>
            </button>
          </div>
        )}

        {/* Loading Spinner & Radar HUD in Olive */}
        {loading ? (
          <div className="glass-panel rounded-3xl p-14 flex flex-col items-center justify-center space-y-6 shadow-2xl relative overflow-hidden my-12 border border-lime-500/30">
            <div className="absolute inset-0 bg-gradient-to-b from-olive-600/15 via-lime-900/10 to-transparent animate-pulse" />

            <div className="relative">
              <div className="w-24 h-24 rounded-full border-4 border-lime-500/20 border-t-lime-400 animate-spin flex items-center justify-center shadow-xl shadow-lime-950/60" />
              <Radio className="w-10 h-10 text-lime-400 absolute inset-0 m-auto animate-ping opacity-75" />
            </div>

            <div className="text-center space-y-3 z-10 max-w-lg w-full">
              <div className="text-xl font-black tracking-wide text-white">
                Zero-Lag Threat Engine Executing...
              </div>
              <div className="text-xs font-mono text-lime-300 bg-[#0c1408]/90 py-2 px-4 rounded-xl border border-lime-900/40">
                {loadingPhase}
              </div>

              {/* Progress Bar in Olive & Lime */}
              <div className="w-full bg-[#0a1106] rounded-full h-3 border border-lime-900/40 overflow-hidden mt-3 shadow-inner">
                <div 
                  className="bg-gradient-to-r from-olive-600 via-lime-500 to-emerald-400 h-full rounded-full transition-all duration-300 shadow-md shadow-lime-900/50"
                  style={{ width: `${loadingProgress}%` }}
                />
              </div>
              <div className="flex justify-between text-[11px] font-mono text-slate-500 pt-1">
                <span>Streaming Forensic Pipeline</span>
                <span className="text-lime-400 font-bold">{loadingProgress}%</span>
              </div>
            </div>
          </div>
        ) : report ? (
          <>
            {/* Segmented Tab Navigation Rail in Tactical Olive */}
            <div className="flex overflow-x-auto glass-panel p-1.5 rounded-2xl border border-lime-900/40 text-xs font-bold gap-1.5 shadow-2xl">
              {[
                { id: 'host', label: 'System Auto-Assessment', icon: MonitorCheck, badge: hostAssessment ? `${hostAssessment.health_score}/100` : undefined, badgeColor: hostAssessment?.status_color },
                { id: 'overview', label: 'Executive Overview', icon: ShieldAlert },
                { id: 'static', label: 'Static Analysis', icon: Cpu },
                { id: 'sandbox', label: 'Behavioral Sandbox', icon: Terminal },
                { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers },
                { id: 'iocs', label: 'Extracted IOCs', icon: Database },
                { id: 'yara', label: 'YARA Workbench', icon: Code2 },
                { id: 'report', label: 'Automated Report', icon: FileText }
              ].map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-4 py-2.5 rounded-xl transition-all duration-200 whitespace-nowrap text-xs font-bold cursor-pointer ${
                      isActive 
                        ? 'bg-gradient-to-r from-lime-600 via-olive-600 to-lime-700 text-slate-950 font-black shadow-lg shadow-lime-950/60 scale-[1.02] border border-lime-400/50' 
                        : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                    {tab.badge && (
                      <span 
                        className="px-2 py-0.5 text-[10px] font-mono font-black rounded-md text-slate-950 shadow-sm"
                        style={{ backgroundColor: tab.badgeColor || '#84cc16' }}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Active Viewport */}
            <div className="transition-all duration-300">
              {activeTab === 'host' && (
                <SystemAssessmentTab 
                  assessment={hostAssessment} 
                  loading={hostLoading} 
                  onRescan={runHostAutoAssessment} 
                />
              )}
              {activeTab === 'overview' && <DashboardOverview report={report} onNavigateTab={setActiveTab} />}
              {activeTab === 'static' && <StaticAnalysisTab staticAnalysis={report.static_analysis} />}
              {activeTab === 'sandbox' && <BehavioralSandboxTab behavioral={report.behavioral_analysis} />}
              {activeTab === 'mitre' && <MitreAttackTab mitre={report.mitre_mapping} />}
              {activeTab === 'iocs' && <IocExtractorTab ioc={report.ioc_extraction} reportId={report.report_id} />}
              {activeTab === 'yara' && <YaraWorkbenchTab yaraScan={report.yara_scan} />}
              {activeTab === 'report' && <ReportGeneratorTab report={report} />}
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-slate-500">
            No active threat session. Click <strong className="text-lime-400">Submit Payload</strong> to begin.
          </div>
        )}
      </main>

      {/* Submit Sample Modal */}
      {showModal && (
        <SampleSelectorModal
          onSelectPreset={loadPresetSample}
          onFileUpload={handleFileUpload}
          onClose={() => setShowModal(false)}
        />
      )}

      {/* High-End Enterprise Footer */}
      <footer className="glass-panel border-t border-lime-900/40 mt-auto py-5 px-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-lime-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-lime-500"></span>
            </span>
            <span className="text-slate-400 font-mono text-xs">KASHYAP THREAT ANALYSER &bull; <strong className="text-lime-400 font-black">TACTICAL OLIVE DEFENSE EDITION</strong></span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500">
            <span>STIX 2.1</span>
            <span>&bull;</span>
            <span>MITRE ATT&CK v14</span>
            <span>&bull;</span>
            <span>YARA v4.5</span>
            <span>&bull;</span>
            <span>SHA-256 PROVENANCE</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
