import React, { useState, useEffect, useRef } from 'react';
import { Upload, FileText, ShieldAlert, Cpu, CheckCircle2, Play, AlertTriangle, FileCode2, Sparkles, X } from 'lucide-react';

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
}

export const SampleSelectorModal: React.FC<Props> = ({ onSelectPreset, onFileUpload, onClose }) => {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    e.stopPropagation();
    setIsDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  };

  const validateAndSubmit = (file: File) => {
    setUploadError(null);
    if (!file) return;
    if (file.size === 0) {
      setUploadError("Selected file is empty (0 bytes). Please select a valid file.");
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
    e.stopPropagation();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSubmit(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSubmit(e.target.files[0]);
      // Reset input value so re-selecting same file works
      e.target.value = '';
    }
  };

  const triggerFileInput = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fadeIn">
      {/* Hidden File Input Accessible via Ref */}
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileChange}
        className="hidden"
        aria-hidden="true"
      />

      <div className="bg-[#0b1407]/95 border border-lime-600/40 w-full max-w-2xl rounded-3xl p-6 sm:p-7 shadow-2xl shadow-lime-950/60 space-y-6 relative overflow-hidden">
        {/* Olive Top Glow Line */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-lime-400 to-transparent" />

        {/* Header */}
        <div className="flex justify-between items-center border-b border-lime-900/30 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-lime-950/80 border border-lime-500/40 flex items-center justify-center text-lime-400 shadow-md">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-black text-white flex items-center gap-2">
                Submit Sample for Deep Threat Analysis
              </h3>
              <p className="text-xs text-lime-300/70 mt-0.5">
                Zero-lag forensic pipeline &bull; Upload any executable, archive or script
              </p>
            </div>
          </div>
          <button 
            type="button"
            onClick={onClose} 
            className="text-slate-400 hover:text-white text-xl font-bold w-8 h-8 rounded-xl hover:bg-lime-950/60 flex items-center justify-center transition cursor-pointer border border-transparent hover:border-lime-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Upload Error Alert */}
        {uploadError && (
          <div className="p-3.5 bg-rose-950/80 border border-rose-500/60 rounded-xl text-rose-200 text-xs flex items-center gap-2.5 shadow-lg animate-fadeIn">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{uploadError}</span>
          </div>
        )}

        {/* Drag & Drop File Upload Area */}
        <div
          onClick={triggerFileInput}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-7 text-center transition-all duration-200 flex flex-col items-center justify-center relative cursor-pointer select-none ${
            isDragActive 
              ? 'border-lime-400 bg-lime-950/40 scale-[1.01] shadow-xl shadow-lime-950/40' 
              : 'border-lime-800/60 hover:border-lime-400 bg-[#0e1909]/80 hover:bg-[#14230b]'
          }`}
        >
          <div className="w-14 h-14 rounded-2xl bg-lime-950/80 border border-lime-500/40 flex items-center justify-center text-lime-300 mb-3 shadow-inner">
            <Upload className="w-7 h-7" />
          </div>

          <div className="text-sm font-bold text-white tracking-wide">
            {isDragActive ? "Release payload here to analyze immediately!" : "Drag & Drop File Payload Here or Click Anywhere"}
          </div>
          <div className="text-xs text-lime-300/70 mt-1">
            Supports Windows PE (EXE, DLL), Linux (ELF), Scripts (PS1, BAT, VBS, PY, PHP), PDF, ZIP
          </div>

          <div className="mt-4 flex items-center gap-3">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                triggerFileInput();
              }}
              className="px-6 py-2.5 bg-gradient-to-r from-lime-600 via-olive-600 to-lime-500 hover:from-lime-500 hover:to-lime-400 text-slate-950 font-black text-xs rounded-xl transition shadow-lg shadow-lime-950/50 cursor-pointer"
            >
              Browse From Computer
            </button>
            <span className="text-[11px] text-slate-500 font-mono">Max size: 100 MB</span>
          </div>
        </div>

        {/* Preset Sample Selector */}
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-lime-300/70 uppercase tracking-wider mb-2.5">
            <span>Or Choose Benchmark Malware Family</span>
            <span className="text-[10px] text-lime-400 font-mono">Instant Emulation</span>
          </div>
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {loading ? (
              <div className="text-xs text-slate-500 italic text-center py-4">Loading benchmark suite...</div>
            ) : (
              presets.map(p => (
                <div
                  key={p.id}
                  onClick={() => onSelectPreset(p.id)}
                  className="bg-[#0e1909]/90 p-3 rounded-xl border border-lime-900/40 hover:border-lime-500/60 hover:bg-[#15250c] cursor-pointer transition flex justify-between items-center group shadow-sm"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-lime-200 text-xs group-hover:text-white transition">{p.name}</span>
                      <span className="px-2 py-0.5 text-[9px] uppercase font-mono font-bold rounded bg-lime-950 text-lime-300 border border-lime-800/60">
                        {p.type}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">{p.description}</div>
                  </div>

                  <button 
                    type="button"
                    className="px-3.5 py-1.5 bg-lime-950/80 group-hover:bg-lime-500 text-lime-200 group-hover:text-slate-950 text-xs font-bold rounded-lg transition flex items-center gap-1 shrink-0 ml-2 border border-lime-900/60 group-hover:border-lime-500 shadow-sm"
                  >
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
