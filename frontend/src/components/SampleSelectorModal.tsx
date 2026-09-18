import React, { useState, useEffect } from 'react';
import { Upload, FileText, ShieldAlert, Cpu, CheckCircle2, Play } from 'lucide-react';

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

  useEffect(() => {
    fetch('/api/samples/presets')
      .then(res => res.json())
      .then(data => {
        setPresets(data);
        setLoading(false);
      })
      .catch(() => {
        // Fallback default presets if backend call is pending
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
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileUpload(e.target.files[0]);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-2xl rounded-2xl p-6 shadow-2xl space-y-6">
        <div className="flex justify-between items-center border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-lg font-black text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" /> Submit Sample for Threat Analysis
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Select a pre-loaded threat sample or upload your custom executable / script payload.
            </p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-lg font-bold">
            &times;
          </button>
        </div>

        {/* Drag & Drop File Upload Area */}
        <div
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          className="border-2 border-dashed border-cyan-500/40 hover:border-cyan-400 bg-slate-950/60 p-6 rounded-xl text-center cursor-pointer transition flex flex-col items-center justify-center"
        >
          <Upload className="w-8 h-8 text-cyan-400 mb-2" />
          <div className="text-sm font-bold text-slate-200">Drag &amp; Drop Sample File Here</div>
          <div className="text-xs text-slate-400 mt-1">Supports EXE, DLL, ELF, Script (PS1, VBS, PY, PHP), PDF, DOCX</div>
          <label className="mt-3 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg cursor-pointer transition">
            Browse File
            <input type="file" onChange={handleFileChange} className="hidden" />
          </label>
        </div>

        {/* Preset Sample Selector */}
        <div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Or Select Benchmark Malware Family</div>
          <div className="space-y-2.5 max-h-56 overflow-y-auto">
            {loading ? (
              <div className="text-xs text-slate-500 italic text-center py-4">Loading preset library...</div>
            ) : (
              presets.map(p => (
                <div
                  key={p.id}
                  onClick={() => onSelectPreset(p.id)}
                  className="bg-slate-950 p-3 rounded-xl border border-slate-800/80 hover:border-cyan-500/60 cursor-pointer transition flex justify-between items-center group"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-cyan-300 text-sm">{p.name}</span>
                      <span className="px-2 py-0.5 text-[10px] uppercase font-bold rounded bg-slate-800 text-slate-400">
                        {p.type}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">{p.description}</div>
                  </div>

                  <button className="px-3 py-1.5 bg-slate-800 group-hover:bg-cyan-500 group-hover:text-slate-950 text-slate-300 text-xs font-bold rounded-lg transition flex items-center gap-1 shrink-0">
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
