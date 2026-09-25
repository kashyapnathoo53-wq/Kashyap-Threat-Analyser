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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fadeIn">
      <div className="bg-[#121215] border border-white/[0.12] w-full max-w-2xl rounded-3xl p-6 sm:p-7 shadow-2xl space-y-6 relative overflow-hidden">
        {/* Subtle Silver Top Line */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-zinc-400 to-transparent" />

        {/* Header */}
        <div className="flex justify-between items-center border-b border-white/[0.08] pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-zinc-900 border border-white/[0.12] flex items-center justify-center text-white shadow-sm">
              <ShieldAlert className="w-5 h-5 text-zinc-200" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight">
                Submit Payload for Analysis
              </h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Upload any executable, archive, document, or script for client-side forensic inspection
              </p>
            </div>
          </div>
          <button 
            type="button"
            onClick={onClose} 
            className="text-zinc-400 hover:text-white w-8 h-8 rounded-xl hover:bg-zinc-800 flex items-center justify-center transition cursor-pointer border border-transparent hover:border-zinc-700"
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

        {/* Direct Transparent Clickable & Droppable Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-7 text-center transition-all duration-200 flex flex-col items-center justify-center relative select-none ${
            isDragActive 
              ? 'border-white bg-zinc-900 scale-[1.01]' 
              : 'border-zinc-700 hover:border-zinc-400 bg-zinc-950/80 hover:bg-zinc-900/60'
          }`}
        >
          {/* Transparent Input covering entire zone */}
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileChange}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-30"
            title="Click or drag any file to upload and analyze"
          />

          <div className="w-12 h-12 rounded-2xl bg-zinc-900 border border-zinc-700 flex items-center justify-center text-zinc-200 mb-3 shadow-sm pointer-events-none">
            <Upload className="w-6 h-6" />
          </div>

          <div className="text-sm font-bold text-white tracking-wide pointer-events-none">
            {isDragActive ? 'Release file to analyze immediately' : 'Drop your file here or click to browse'}
          </div>
          <div className="text-xs text-zinc-400 mt-1 pointer-events-none">
            Supports EXE, DLL, PDF, ZIP, DOCX, JS, PY, PHP, ELF, and any raw binary
          </div>

          <div className="mt-4 flex items-center gap-3 pointer-events-none">
            <span className="px-5 py-2 bg-white text-zinc-950 font-bold text-xs rounded-xl shadow-md">
              Browse From Computer
            </span>
            <span className="text-[11px] text-zinc-500 font-mono">Up to 100 MB</span>
          </div>
        </div>

        {/* Preset Sample Selector */}
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2.5">
            <span>Or Analyze Standard Benchmark Malware</span>
            <span className="text-[10px] text-zinc-400 font-mono">Instant Emulation</span>
          </div>
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {loading ? (
              <div className="text-xs text-zinc-500 italic text-center py-4">Loading benchmark suite...</div>
            ) : (
              presets.map(p => (
                <div
                  key={p.id}
                  onClick={() => onSelectPreset(p.id)}
                  className="bg-zinc-950/70 p-3 rounded-xl border border-white/[0.08] hover:border-white/30 hover:bg-zinc-900 cursor-pointer transition flex justify-between items-center group shadow-sm"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-zinc-100 text-xs group-hover:text-white transition">{p.name}</span>
                      <span className="px-2 py-0.5 text-[9px] uppercase font-mono font-bold rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                        {p.type}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-400">{p.description}</div>
                  </div>

                  <button 
                    type="button"
                    className="px-3.5 py-1.5 bg-zinc-800 group-hover:bg-white text-zinc-200 group-hover:text-zinc-950 text-xs font-bold rounded-lg transition flex items-center gap-1 shrink-0 ml-2 border border-zinc-700 group-hover:border-white shadow-sm"
                  >
                    <Play className="w-3.5 h-3.5" /> Select
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
