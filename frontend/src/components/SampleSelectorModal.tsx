import React, { useState, useEffect } from 'react';
import { Upload, FileText, ShieldAlert, Cpu, CheckCircle2, Play, AlertTriangle, FileCode2, Sparkles } from 'lucide-react';

interface Preset {
  id: string;
  name: string;
  type: string;
  description: string;
}

interface Props {
  onSelectPreset: (presetId: string) => void;
  onFileUpload: (file: File) => void;
  onClose: () => void;
  isUploading?: boolean;
}

export const SampleSelectorModal: React.FC<Props> = ({ onSelectPreset, onFileUpload, onClose, isUploading = false }) => {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/samples/presets')
      .then(res => res.json())
      .then(data => {
        setPresets(data);
        setLoading(false);
      })
      .catch(() => {
        setPresets([
          { id: 'sample_wannacry', name: 'WannaCry_Ransomware.exe', type: 'Ransomware Payload', description: 'Deletes shadow copies, encrypts documents, and beacons to Tor C2.' },
          { id: 'sample_emotet', name: 'Emotet_Infostealer.exe', type: 'Infostealer Trojan', description: 'Steals browser credentials, DPAPI secrets, and posts to dropzone.' },
          { id: 'sample_cobaltstrike', name: 'CobaltStrike_Beacon.dll', type: 'C2 Beacon', description: 'Injects shellcode into svchost/notepad via NtUnmapViewOfSection.' },
          { id: 'sample_webshell', name: 'c99_webshell.php', type: 'PHP WebShell', description: 'Backdoor command execution script.' },
          { id: 'sample_benign_calc', name: 'Calculator_Utility.exe', type: 'Benign Application', description: 'Clean system binary utility.' }
        ]);
        setLoading(false);
      });
  }, []);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = () => {
    setIsDragActive(false);
  };

  const validateAndSubmit = (file: File) => {
    setUploadError(null);
    if (!file) return;
    if (file.size === 0) {
      setUploadError("Selected file is 0 bytes. Please select a valid file.");
      return;
    }
    if (file.size > 104857600) {
      setUploadError(`File is too large (${(file.size / (1024 * 1024)).toFixed(1)} MB). Maximum limit is 100 MB.`);
      return;
    }
    onFileUpload(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSubmit(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSubmit(e.target.files[0]);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fadeIn">
      <div className="bg-slate-900/95 border border-cyan-500/40 w-full max-w-2xl rounded-2xl p-6 shadow-2xl shadow-cyan-950/50 space-y-6 relative overflow-hidden">
        {/* Glow Header Accent */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-cyan-500 to-transparent" />

        <div className="flex justify-between items-center border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-black text-white flex items-center gap-2">
                Submit Sample for Deep Threat Analysis
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Zero-lag streaming analysis: upload custom executable/script or choose a threat family preset.
              </p>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="text-slate-400 hover:text-white text-xl font-bold w-8 h-8 rounded-lg hover:bg-slate-800 flex items-center justify-center transition"
          >
            &times;
          </button>
        </div>

        {/* Upload Error Alert */}
        {uploadError && (
          <div className="p-3.5 bg-rose-950/60 border border-rose-500/50 rounded-xl text-rose-300 text-xs flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{uploadError}</span>
          </div>
        )}

        {/* Drag & Drop File Upload Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-7 text-center transition-all flex flex-col items-center justify-center relative overflow-hidden ${
            isDragActive 
              ? 'border-cyan-400 bg-cyan-500/10 scale-[1.01] shadow-lg shadow-cyan-500/20' 
              : 'border-slate-700/80 hover:border-cyan-500/60 bg-slate-950/60'
          }`}
        >
          <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-3 shadow-inner">
            <Upload className="w-7 h-7" />
          </div>

          <div className="text-sm font-bold text-white tracking-wide">
            {isDragActive ? "Drop binary payload here to scan!" : "Drag & Drop File Payload Here"}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Supports Windows PE (EXE, DLL), Linux (ELF), Scripts (PS1, BAT, VBS, PY, PHP), PDF, ZIP
          </div>

          <div className="mt-4 flex items-center gap-3">
            <label className="px-5 py-2 bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-black text-xs rounded-xl cursor-pointer transition shadow-lg shadow-cyan-500/20">
              Browse From Computer
              <input type="file" onChange={handleFileChange} className="hidden" />
            </label>
            <span className="text-[11px] text-slate-500 font-mono">Max size: 100 MB</span>
          </div>
        </div>

        {/* Preset Sample Selector */}
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-400 uppercase tracking-wider mb-2.5">
            <span>Or Choose Benchmark Malware Family</span>
            <span className="text-[10px] text-cyan-400 font-mono">Instant Emulation</span>
          </div>
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {loading ? (
              <div className="text-xs text-slate-500 italic text-center py-4">Loading benchmark suite...</div>
            ) : (
              presets.map(p => (
                <div
                  key={p.id}
                  onClick={() => onSelectPreset(p.id)}
                  className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/90 hover:border-cyan-500/60 hover:bg-slate-950 cursor-pointer transition flex justify-between items-center group"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-cyan-300 text-xs">{p.name}</span>
                      <span className="px-2 py-0.5 text-[9px] uppercase font-bold rounded bg-slate-800 text-slate-300">
                        {p.type}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">{p.description}</div>
                  </div>

                  <button className="px-3 py-1.5 bg-slate-800 group-hover:bg-cyan-500 group-hover:text-slate-950 text-slate-300 text-xs font-bold rounded-lg transition flex items-center gap-1 shrink-0 ml-2">
                    <Play className="w-3.5 h-3.5" /> Analyze
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
