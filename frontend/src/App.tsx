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
import { Shield, ShieldAlert, Cpu, Terminal, Layers, Database, Code2, FileText, Upload, RefreshCw, Activity, AlertTriangle, MonitorCheck } from 'lucide-react';

export const App: React.FC = () => {
  const [report, setReport] = useState<FullAnalysisReport | null>(null);
  const [hostAssessment, setHostAssessment] = useState<HostAssessment | null>(null);
  const [hostLoading, setHostLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('host');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  // Auto-run Host Assessment and load sample on startup
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

  const loadPresetSample = async (presetId: string) => {
    setLoading(true);
    try {
      const res = await fetch('/api/analyze/preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_id: presetId })
      });
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      }
    } catch (err) {
      console.error("Analysis API failed:", err);
    } finally {
      setLoading(false);
      setShowModal(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/analyze/upload', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      }
    } catch (err) {
      console.error("Upload API failed:", err);
    } finally {
      setLoading(false);
      setShowModal(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0f1d] text-slate-100 font-sans flex flex-col">
      {/* Top Header Navigation */}
      <header className="bg-slate-900/90 border-b border-slate-800 sticky top-0 z-40 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-slate-950 font-black" />
            </div>
            <div>
              <h1 className="text-base font-black tracking-tight text-white flex items-center gap-2">
                KASHYAP THREAT ANALYSER <span className="text-xs font-mono font-normal px-2 py-0.5 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded">v2.0</span>
              </h1>
              <p className="text-[11px] text-slate-400">Automated Static &amp; Behavioral Malware Threat Analysis</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {hostAssessment && (
              <button 
                onClick={() => setActiveTab('host')}
                className="hidden lg:flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs hover:border-cyan-500 transition"
              >
                <MonitorCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-slate-400">Host Status:</span>
                <span 
                  className="px-2 py-0.5 rounded text-[10px] font-bold text-white uppercase"
                  style={{ backgroundColor: hostAssessment.status_color }}
                >
                  {hostAssessment.health_score}/100
                </span>
              </button>
            )}

            {report && (
              <div className="hidden md:flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono">
                <span className="text-slate-400">Sample:</span>
                <span className="text-cyan-400 font-bold">{report.sample_name}</span>
                <span 
                  className="px-2 py-0.5 rounded text-[10px] font-bold text-white uppercase ml-1"
                  style={{ backgroundColor: report.threat_scoring.color }}
                >
                  {report.threat_scoring.severity}
                </span>
              </div>
            )}

            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs transition shadow-lg shadow-cyan-600/20"
            >
              <Upload className="w-4 h-4" /> Analyze New Sample
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {loading ? (
          <div className="h-96 flex flex-col items-center justify-center space-y-4">
            <RefreshCw className="w-10 h-10 text-cyan-400 animate-spin" />
            <div className="text-sm font-bold text-slate-300">Emulating Behavioral Execution &amp; Scanning Hashes...</div>
            <div className="text-xs text-slate-500 font-mono">Running Static Analyzer, YARA Engine, IOC Extractor &amp; ATT&amp;CK Mapper</div>
          </div>
        ) : report ? (
          <>
            {/* Tab Navigation Controls */}
            <div className="flex overflow-x-auto bg-slate-900/80 p-1.5 rounded-xl border border-slate-800 text-xs font-semibold gap-1">
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
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg transition whitespace-nowrap ${
                      isActive 
                        ? 'bg-cyan-500 text-slate-950 font-bold shadow-md' 
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                    {tab.badge && (
                      <span 
                        className="px-1.5 py-0.2 text-[10px] font-mono font-bold rounded text-white"
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
          <div className="text-center py-20 text-slate-500">No report available. Click Analyze New Sample.</div>
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
      <footer className="bg-slate-950 border-t border-slate-800/80 py-4 text-center text-xs text-slate-500">
        Kashyap Threat Analyser - Automated Malware Static &amp; Behavioral Analysis Platform &copy; 2026
      </footer>
    </div>
  );
};

export default App;
