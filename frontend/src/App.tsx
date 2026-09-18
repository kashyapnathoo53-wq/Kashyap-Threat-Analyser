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
import { Shield, ShieldAlert, Cpu, Terminal, Layers, Database, Code2, FileText, Upload, RefreshCw, Activity, AlertTriangle, MonitorCheck, Zap, Clock, CheckCircle2, Radio } from 'lucide-react';

export const App: React.FC = () => {
  const [report, setReport] = useState<FullAnalysisReport | null>(null);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment | null>(null);
  const [hostLoading, setHostLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingPhase, setLoadingPhase] = useState<string>('Initializing analysis engine...');
  const [loadingProgress, setLoadingProgress] = useState<number>(10);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Auto-run Host Assessment and load initial benchmark sample on startup
  useEffect(() => {
    runHostAutoAssessment();
    loadPresetSample('sample_wannacry');
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
    setLoadingProgress(15);
    setLoadingPhase("Phase 1/4: Ingesting binary payload & calculating cryptographic hashes...");
    
    const t1 = setTimeout(() => {
      setLoadingProgress(45);
      setLoadingPhase("Phase 2/4: Computing section entropy profile & testing for packers...");
    }, 150);

    const t2 = setTimeout(() => {
      setLoadingProgress(75);
      setLoadingPhase("Phase 3/4: Executing YARA rulesets & auto-decoding XOR/Base64 strings...");
    }, 300);

    const t3 = setTimeout(() => {
      setLoadingProgress(95);
      setLoadingPhase("Phase 4/4: Emulating behavioral process sandbox & mapping MITRE TTPs...");
    }, 450);

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
      setErrorMessage("Could not communicate with Kashyap Threat Analyser backend.");
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
        setErrorMessage(errData.detail || `Upload failed with status code ${res.status}`);
      }
    } catch (err: any) {
      console.error("Upload API failed:", err);
      setErrorMessage(err?.message || "File upload failed. Ensure the backend server is running.");
    } finally {
      cancelSim();
      setLoading(false);
      setShowModal(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-slate-950">
      {/* Top Header Navigation HUD */}
      <header className="bg-slate-900/90 border-b border-cyan-500/20 sticky top-0 z-40 backdrop-blur-xl shadow-2xl shadow-cyan-950/20">
        <div className="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-500 via-cyan-400 to-purple-600 p-[1px] shadow-lg shadow-cyan-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-slate-950 rounded-2xl flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400 font-black" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-black tracking-wider text-white">
                  KASHYAP THREAT ANALYSER
                </h1>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 rounded-full">
                  v2.0 SOC GRID
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                Automated Static, Behavioral &amp; Host Malware Threat Intelligence
              </p>
            </div>
          </div>

          {/* Quick Telemetry & Actions */}
          <div className="flex items-center gap-3">
            {hostAssessment && (
              <button 
                onClick={() => setActiveTab('host')}
                className="hidden lg:flex items-center gap-2 bg-slate-950/90 px-3 py-1.5 rounded-xl border border-slate-800 text-xs hover:border-cyan-500/50 transition group"
              >
                <MonitorCheck className="w-4 h-4 text-cyan-400 group-hover:animate-pulse" />
                <span className="text-slate-400">Host Security:</span>
                <span 
                  className="px-2 py-0.5 rounded text-[10px] font-mono font-black text-white"
                  style={{ backgroundColor: hostAssessment.status_color }}
                >
                  {hostAssessment.health_score}/100
                </span>
              </button>
            )}

            {report && (
              <div className="hidden md:flex items-center gap-2.5 bg-slate-950/90 px-3 py-1.5 rounded-xl border border-slate-800 text-xs font-mono">
                <span className="text-slate-500">Sample:</span>
                <span className="text-cyan-300 font-bold max-w-[140px] truncate" title={report.sample_name}>
                  {report.sample_name}
                </span>
                <span 
                  className="px-2 py-0.5 rounded text-[10px] font-bold text-white uppercase"
                  style={{ backgroundColor: report.threat_scoring.color }}
                >
                  {report.threat_scoring.severity}
                </span>
                {(report as any).analysis_duration_ms && (
                  <span className="text-[10px] text-slate-500 flex items-center gap-1 border-l border-slate-800 pl-2">
                    <Zap className="w-3 h-3 text-amber-400" />
                    {(report as any).analysis_duration_ms}ms
                  </span>
                )}
              </div>
            )}

            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-black rounded-xl text-xs transition shadow-lg shadow-cyan-500/25"
            >
              <Upload className="w-4 h-4" /> Analyze New Sample
            </button>
          </div>
        </div>
      </header>

      {/* Error Banner if any */}
      {errorMessage && (
        <div className="bg-rose-950/70 border-b border-rose-500/50 px-4 py-3 text-xs text-rose-200 flex items-center justify-between max-w-7xl mx-auto w-full mt-4 rounded-xl">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span><strong>Notice:</strong> {errorMessage}</span>
          </div>
          <button 
            onClick={() => setErrorMessage(null)} 
            className="text-slate-400 hover:text-white px-2 py-0.5 rounded bg-slate-900"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {loading ? (
          <div className="bg-slate-900/80 border border-cyan-500/30 rounded-3xl p-12 flex flex-col items-center justify-center space-y-6 shadow-2xl relative overflow-hidden my-12">
            <div className="absolute inset-0 bg-cyan-500/5 animate-pulse" />

            <div className="relative">
              <div className="w-20 h-20 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center shadow-lg shadow-cyan-500/20" />
              <Radio className="w-8 h-8 text-cyan-300 absolute inset-0 m-auto animate-ping opacity-60" />
            </div>

            <div className="text-center space-y-2 z-10 max-w-md w-full">
              <div className="text-lg font-black tracking-wide text-white">
                Zero-Lag Threat Engine Executing...
              </div>
              <div className="text-xs font-mono text-cyan-300">
                {loadingPhase}
              </div>

              {/* Progress Bar */}
              <div className="w-full bg-slate-950 rounded-full h-2.5 border border-slate-800 overflow-hidden mt-4">
                <div 
                  className="bg-gradient-to-r from-cyan-500 to-purple-500 h-full rounded-full transition-all duration-300"
                  style={{ width: `${loadingProgress}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-slate-500 pt-1">
                Streaming Hash &amp; Emulation Pipeline: {loadingProgress}%
              </div>
            </div>
          </div>
        ) : report ? (
          <>
            {/* Tab Navigation Controls */}
            <div className="flex overflow-x-auto bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800/90 text-xs font-semibold gap-1.5 shadow-xl">
              {[
                { id: 'host', label: 'System Auto-Assessment', icon: MonitorCheck, badge: hostAssessment ? `${hostAssessment.health_score}/100` : undefined, badgeColor: hostAssessment?.status_color },
                { id: 'overview', label: 'Sample Overview', icon: ShieldAlert },
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
                    className={`flex items-center gap-2 px-3.5 py-2.5 rounded-xl transition-all whitespace-nowrap font-bold ${
                      isActive 
                        ? 'bg-gradient-to-r from-cyan-500 to-cyan-400 text-slate-950 shadow-md shadow-cyan-500/20' 
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/80'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                    {tab.badge && (
                      <span 
                        className="px-1.5 py-0.2 text-[9px] font-mono font-black rounded text-white"
                        style={{ backgroundColor: tab.badgeColor || '#22c55e' }}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Tab Body Viewports */}
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
          </>
        ) : (
          <div className="text-center py-20 text-slate-500">
            No report available. Click <strong className="text-cyan-400">Analyze New Sample</strong> to begin.
          </div>
        )}
      </main>

      {/* Modal */}
      {showModal && (
        <SampleSelectorModal
          onSelectPreset={loadPresetSample}
          onFileUpload={handleFileUpload}
          onClose={() => setShowModal(false)}
        />
      )}

      {/* Footer */}
      <footer className="bg-slate-950 border-t border-slate-900 py-4 text-center text-xs text-slate-500 font-mono">
        Kashyap Threat Analyser &bull; Advanced Cyber Threat Intelligence &bull; &copy; 2026
      </footer>
    </div>
  );
};

export default App;
