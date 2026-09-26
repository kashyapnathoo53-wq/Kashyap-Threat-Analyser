import React, { useState, useRef } from 'react';
import { HostAssessment } from '../types';
import { scanLocalFiles, DeviceScanSummary, ScannedFileResult } from '../utils/clientFolderScanner';
import { explainHostInPlainEnglish } from '../utils/plainLanguageAdvisor';
import { cyberAudio } from '../utils/cyberAudio';
import { jarvisVoice } from '../utils/jarvisVoice';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, FolderSearch, FileText, 
  CheckCircle2, RefreshCw, Cpu, HardDrive, Smartphone, Monitor,
  Volume2, Bot, ArrowRight, Trash2, Download, Search, Info
} from 'lucide-react';

interface Props {
  hostAssessment: HostAssessment;
  onUpdateHostScore: (newScore: number, status: string, color: string) => void;
  onOpenJarvisChat: (prompt?: string) => void;
}

export const DeviceSentinelTab: React.FC<Props> = ({
  hostAssessment,
  onUpdateHostScore,
  onOpenJarvisChat
}) => {
  const [fileScan, setFileScan] = useState<DeviceScanSummary | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number; filename: string }>({
    current: 0,
    total: 0,
    filename: ''
  });
  const [filter, setFilter] = useState<'ALL' | 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const folderInputRef = useRef<HTMLInputElement | null>(null);
  const filesInputRef = useRef<HTMLInputElement | null>(null);

  const plainExplanation = explainHostInPlainEnglish(hostAssessment, fileScan);

  const handleStartScanning = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    
    cyberAudio.playDataStream();
    setIsScanning(true);
    setScanProgress({ current: 0, total: fileList.length, filename: 'Preparing forensic pipeline...' });

    try {
      const filesArray = Array.from(fileList);
      const summary = await scanLocalFiles(filesArray, (processed, total, currentName) => {
        setScanProgress({ current: processed, total, filename: currentName });
      });

      setFileScan(summary);
      
      // Update parent Arc Reactor score to reflect this user's real file audit!
      let newStatus = 'HARDENED / SECURE';
      let newColor = '#10b981';
      if (summary.dangerousCount > 0) {
        newStatus = 'THREAT DETECTED';
        newColor = '#ef4444';
        cyberAudio.playAlarm();
      } else if (summary.suspiciousCount > 0) {
        newStatus = 'REVIEW ADVISED';
        newColor = '#f59e0b';
        cyberAudio.playRadarSweep();
      } else {
        cyberAudio.playRadarSweep();
      }

      onUpdateHostScore(summary.overallScore, newStatus, newColor);

      // Play J.A.R.V.I.S. plain English briefing
      const voiceScript = `Host file audit completed on ${hostAssessment.host_info.os}. Scanned ${summary.totalFilesScanned} items. ${summary.plainEnglishVerdict}`;
      jarvisVoice.speak(voiceScript, 'system');

    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handlePickDirectory = async () => {
    cyberAudio.playClick();
    // Try modern File System Access API if supported by Chrome/Edge
    if ('showDirectoryPicker' in window) {
      try {
        const dirHandle = await (window as any).showDirectoryPicker();
        const files: File[] = [];
        for await (const entry of dirHandle.values()) {
          if (entry.kind === 'file') {
            const file = await entry.getFile();
            files.push(file);
          }
        }
        if (files.length > 0) {
          const dataTransfer = new DataTransfer();
          files.forEach(f => dataTransfer.items.add(f));
          handleStartScanning(dataTransfer.files);
          return;
        }
      } catch (err: any) {
        if (err.name !== 'AbortError') {
          folderInputRef.current?.click();
        }
        return;
      }
    }
    // Fallback to standard input
    folderInputRef.current?.click();
  };

  const filteredResults = fileScan?.results.filter(item => {
    if (filter === 'DANGEROUS' && item.status !== 'DANGEROUS') return false;
    if (filter === 'SUSPICIOUS' && item.status !== 'SUSPICIOUS') return false;
    if (filter === 'SAFE' && item.status !== 'SAFE') return false;
    if (searchQuery && !item.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  }) || [];

  const isMobile = /Android|iPhone|iPad/i.test(hostAssessment.host_info.os);

  return (
    <div className="space-y-6">
      {/* Hidden File / Directory inputs */}
      <input 
        ref={folderInputRef}
        type="file" 
        multiple
        // @ts-ignore
        webkitdirectory="true" 
        className="hidden" 
        onChange={(e) => handleStartScanning(e.target.files)} 
      />
      <input 
        ref={filesInputRef}
        type="file" 
        multiple 
        className="hidden" 
        onChange={(e) => handleStartScanning(e.target.files)} 
      />

      {/* Hero Plain Language Investigator Card */}
      <div className="glass-panel p-6 sm:p-8 rounded-3xl border border-white/[0.08] relative overflow-hidden shadow-2xl bg-zinc-950/85">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          
          <div className="space-y-3 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2.5">
              <span 
                className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-sm"
                style={{ 
                  backgroundColor: `${plainExplanation.badgeColor}20`,
                  color: plainExplanation.badgeColor,
                  border: `1px solid ${plainExplanation.badgeColor}40`
                }}
              >
                {plainExplanation.badgeColor === '#10b981' ? (
                  <ShieldCheck className="w-3.5 h-3.5" />
                ) : (
                  <ShieldAlert className="w-3.5 h-3.5" />
                )}
                {plainExplanation.statusBadge}
              </span>

              <span className="text-xs font-mono text-zinc-400 bg-zinc-900/90 px-2.5 py-0.5 rounded-lg border border-white/[0.06]">
                {plainExplanation.deviceDetails}
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight leading-snug">
              {plainExplanation.headline}
            </h2>

            <p className="text-sm text-zinc-300 leading-relaxed">
              {plainExplanation.summary}
            </p>

            {/* Plain language bullet points */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              {plainExplanation.keyPoints.map((pt, i) => (
                <div key={i} className="bg-zinc-900/70 p-3 rounded-2xl border border-white/[0.06]">
                  <div className="text-base mb-1">{pt.icon}</div>
                  <div className="text-xs font-bold text-white mb-0.5">{pt.title}</div>
                  <div className="text-[11px] text-zinc-400 leading-relaxed">{pt.explanation}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Action CTA Card */}
          <div className="w-full lg:w-72 bg-zinc-900/80 p-5 rounded-2xl border border-white/[0.08] text-center space-y-3 shrink-0 shadow-lg">
            <div className="text-xs font-mono text-zinc-400 uppercase tracking-wider font-bold">
              Local File &amp; Folder Audit
            </div>
            
            <p className="text-xs text-zinc-400 leading-relaxed">
              Scan your <strong>Downloads</strong>, <strong>Desktop</strong>, or selected folders for hidden viruses or deceptive programs directly inside your browser.
            </p>

            <button
              onClick={handlePickDirectory}
              disabled={isScanning}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-r from-zinc-100 to-zinc-300 hover:from-white hover:to-zinc-200 text-zinc-950 font-black rounded-xl text-xs transition shadow-md hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <FolderSearch className="w-4 h-4 text-zinc-900" />
              <span>{isScanning ? 'Analyzing Files...' : 'Scan Folder / Files'}</span>
            </button>

            <div className="text-[10px] text-zinc-500 font-mono">
              100% Private &bull; Scanned directly on your device
            </div>
          </div>

        </div>
      </div>

      {/* Live Scan Progress Indicator */}
      {isScanning && (
        <div className="glass-panel p-5 rounded-2xl border border-cyan-500/40 animate-pulse bg-zinc-950/90 shadow-xl space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-zinc-200 font-bold flex items-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
              Analyzing file {scanProgress.current} of {scanProgress.total}...
            </span>
            <span className="text-cyan-400 font-bold">
              {Math.round((scanProgress.current / Math.max(1, scanProgress.total)) * 100)}%
            </span>
          </div>
          <div className="w-full bg-zinc-900 rounded-full h-2 overflow-hidden border border-white/[0.08]">
            <div 
              className="bg-gradient-to-r from-cyan-400 to-blue-500 h-full transition-all duration-150"
              style={{ width: `${Math.round((scanProgress.current / Math.max(1, scanProgress.total)) * 100)}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-zinc-400 truncate">
            Current Target: <strong className="text-zinc-200">{scanProgress.filename}</strong>
          </div>
        </div>
      )}

      {/* Real-time File Scan Findings (If Scanned) */}
      {fileScan && (
        <div className="glass-panel p-6 rounded-3xl border border-white/[0.08] bg-zinc-950/85 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.06] pb-4">
            <div>
              <h3 className="text-lg font-black text-white flex items-center gap-2">
                <span>Investigated File Results</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-zinc-900 border border-white/[0.08] text-zinc-300">
                  {fileScan.totalFilesScanned} Files
                </span>
              </h3>
              <p className="text-xs text-zinc-400 mt-1">
                {fileScan.plainEnglishVerdict}
              </p>
            </div>

            {/* Filter buttons */}
            <div className="flex items-center gap-1.5 flex-wrap font-mono text-xs">
              <button
                onClick={() => setFilter('ALL')}
                className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                  filter === 'ALL' ? 'bg-white text-zinc-950 font-bold' : 'bg-zinc-900 text-zinc-400 hover:text-white'
                }`}
              >
                All ({fileScan.totalFilesScanned})
              </button>
              {fileScan.dangerousCount > 0 && (
                <button
                  onClick={() => setFilter('DANGEROUS')}
                  className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                    filter === 'DANGEROUS' ? 'bg-red-500 text-white font-bold' : 'bg-red-950/60 text-red-400 hover:bg-red-900'
                  }`}
                >
                  Dangerous ({fileScan.dangerousCount})
                </button>
              )}
              {fileScan.suspiciousCount > 0 && (
                <button
                  onClick={() => setFilter('SUSPICIOUS')}
                  className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                    filter === 'SUSPICIOUS' ? 'bg-amber-500 text-zinc-950 font-bold' : 'bg-amber-950/60 text-amber-300 hover:bg-amber-900'
                  }`}
                >
                  Suspicious ({fileScan.suspiciousCount})
                </button>
              )}
              <button
                onClick={() => setFilter('SAFE')}
                className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                  filter === 'SAFE' ? 'bg-emerald-500 text-white font-bold' : 'bg-emerald-950/60 text-emerald-400 hover:bg-emerald-900'
                }`}
              >
                Safe ({fileScan.safeCount})
              </button>
            </div>
          </div>

          {/* Search bar */}
          <div className="relative">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3.5 top-3" />
            <input 
              type="text"
              placeholder="Search scanned files by name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-zinc-900/80 border border-white/[0.08] focus:border-zinc-500 rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-zinc-500 focus:outline-none"
            />
          </div>

          {/* Scanned files list */}
          <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1">
            {filteredResults.length === 0 ? (
              <div className="text-center py-8 text-xs text-zinc-500">
                No files matching your filter criteria.
              </div>
            ) : (
              filteredResults.map(item => (
                <div 
                  key={item.id}
                  className={`p-3.5 rounded-2xl border transition flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                    item.status === 'DANGEROUS'
                      ? 'bg-red-950/30 border-red-500/40 text-red-200'
                      : item.status === 'SUSPICIOUS'
                      ? 'bg-amber-950/20 border-amber-500/30 text-amber-200'
                      : 'bg-zinc-900/60 border-white/[0.06] text-zinc-300'
                  }`}
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-black ${
                        item.status === 'DANGEROUS'
                          ? 'bg-red-500 text-white'
                          : item.status === 'SUSPICIOUS'
                          ? 'bg-amber-500 text-zinc-950'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}>
                        {item.status}
                      </span>
                      <span className="text-xs font-bold text-white truncate max-w-sm" title={item.name}>
                        {item.name}
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        ({Math.round(item.size / 1024)} KB)
                      </span>
                    </div>

                    <p className="text-xs text-zinc-400">
                      {item.plainEnglishReason}
                    </p>

                    <div className="text-[11px] font-mono text-zinc-500 flex flex-wrap items-center gap-3">
                      <span>SHA256: {item.sha256.slice(0, 16)}...</span>
                      <span>Entropy: {item.entropy}/8.0</span>
                      {item.status !== 'SAFE' && (
                        <span className="text-amber-400 font-bold">&bull; Action: {item.recommendation}</span>
                      )}
                    </div>
                  </div>

                  {item.status !== 'SAFE' && (
                    <button
                      onClick={() => onOpenJarvisChat(`How do I safely remove or inspect this file: ${item.name}? Reason: ${item.plainEnglishReason}`)}
                      className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white text-xs font-bold font-mono transition shrink-0 flex items-center gap-1 border border-white/[0.1] cursor-pointer"
                    >
                      <Bot className="w-3.5 h-3.5 text-zinc-300" />
                      <span>Ask J.A.R.V.I.S.</span>
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* System Hardware & Defense Posture Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="glass-card p-4 rounded-2xl border border-white/[0.08] bg-zinc-900/60">
          <div className="flex items-center gap-2 text-xs font-bold text-white mb-1">
            {isMobile ? <Smartphone className="w-4 h-4 text-zinc-400" /> : <Monitor className="w-4 h-4 text-zinc-400" />}
            <span>Host Environment</span>
          </div>
          <div className="text-sm font-black text-white">{hostAssessment.host_info.os}</div>
          <div className="text-xs text-zinc-400 mt-0.5">
            Architecture: {hostAssessment.host_info.architecture}
          </div>
        </div>

        <div className="glass-card p-4 rounded-2xl border border-white/[0.08] bg-zinc-900/60">
          <div className="flex items-center gap-2 text-xs font-bold text-white mb-1">
            <Cpu className="w-4 h-4 text-zinc-400" />
            <span>Process &amp; Memory Isolation</span>
          </div>
          <div className="text-sm font-black text-emerald-400">HARDENED SANDBOX</div>
          <div className="text-xs text-zinc-400 mt-0.5">
            {hostAssessment.summary.total_processes_scanned} Monitored System Handles
          </div>
        </div>

        <div className="glass-card p-4 rounded-2xl border border-white/[0.08] bg-zinc-900/60">
          <div className="flex items-center gap-2 text-xs font-bold text-white mb-1">
            <HardDrive className="w-4 h-4 text-zinc-400" />
            <span>Storage &amp; Registry Shield</span>
          </div>
          <div className="text-sm font-black text-white">SECURE STORAGE</div>
          <div className="text-xs text-zinc-400 mt-0.5">
            Zero Unauthorized Autostart RunKeys
          </div>
        </div>
      </div>
    </div>
  );
};
