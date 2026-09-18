import React, { useState } from 'react';
import { StaticAnalysis } from '../types';
import { SectionGuide } from './SectionGuide';
import { Copy, Check, FileCode, Cpu, Code2, Search, Lock, Binary, ShieldAlert, Key, Zap } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

interface Props {
  staticAnalysis: StaticAnalysis;
}

export const StaticAnalysisTab: React.FC<Props> = ({ staticAnalysis }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [stringFilter, setStringFilter] = useState('');
  const [stringTab, setStringTab] = useState<'decoded' | 'ascii' | 'unicode'>('decoded');

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const entropyData = staticAnalysis.pe_structure.sections.map(s => ({
    name: s.name,
    entropy: s.entropy,
    isSuspicious: s.is_suspicious
  }));

  const filteredDecoded = staticAnalysis.strings.decoded.filter(
    s => s.decoded.toLowerCase().includes(stringFilter.toLowerCase()) || s.type.toLowerCase().includes(stringFilter.toLowerCase())
  );

  const filteredAscii = staticAnalysis.strings.ascii.filter(
    s => s.toLowerCase().includes(stringFilter.toLowerCase())
  );

  const filteredUnicode = staticAnalysis.strings.unicode.filter(
    s => s.toLowerCase().includes(stringFilter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="Static Malware Forensics &amp; Structural Disassembly"
        badge="Binary Forensics"
        whatItDoes="Inspects the file without executing its code. It extracts cryptographic hashes (MD5, SHA1, SHA256, SSDEEP fuzzy hash), parses Portable Executable (PE) headers, measures Shannon entropy per section (.text, .rdata, .data, .rsrc) to detect packers like UPX or Themida, and identifies high-risk Windows API functions imported from KERNEL32 and ADVAPI32."
        howItHelps="Static analysis reveals the binary's underlying capabilities, obfuscation level, and origin without running any dangerous payloads. Comparing SSDEEP hashes lets you identify malware polymorphic variants that share code even if their SHA256 has changed."
        keyIndicators={[
          { label: "Entropy > 7.1", detail: "Indicates encrypted shellcode or commercial packers (UPX, Themida, ASPack)", severity: "critical" },
          { label: "VirtualAllocEx + WriteProcessMemory", detail: "Classic indicator of Process Injection / Process Hollowing into foreign processes", severity: "critical" },
          { label: "Digital Signature: UNSIGNED", detail: "Legitimate enterprise software is digitally signed; malware is almost always unsigned or self-signed", severity: "high" },
          { label: "Decoded Base64/XOR", detail: "Malware authors hide C2 URLs and PowerShell commands using simple XOR/Base64 encodings", severity: "high" },
          { label: "Unusual Section Names", detail: "Sections outside standard names (.UPX0, .evil, .vmp) suggest custom packing or stealth loaders", severity: "info" }
        ]}
        analystTip="Inspect the Decoded Strings sub-tab first. Attackers frequently leave C2 URLs, IP addresses, or batch commands obfuscated via single-byte XOR keys (0x5A, 0x13, 0x37) that our auto-decoder recovers."
        defaultExpanded={false}
      />

      {/* Cryptographic File Hashes Grid */}
      <div className="glass-card p-6 rounded-3xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" /> Cryptographic File Fingerprints
            </h3>
            <p className="text-xs text-slate-400">
              Immutable cryptographic hashes for threat intelligence cross-referencing and chain of custody
            </p>
          </div>
          <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/80 px-2.5 py-1 rounded-lg border border-cyan-800/50">
            {staticAnalysis.hashes.size_bytes} Bytes ({ (staticAnalysis.hashes.size_bytes / 1024).toFixed(1) } KB)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 font-mono text-xs">
          {[
            { label: 'MD5', val: staticAnalysis.hashes.md5 },
            { label: 'SHA1', val: staticAnalysis.hashes.sha1 },
            { label: 'SHA256', val: staticAnalysis.hashes.sha256 },
            { label: 'SSDEEP (Fuzzy)', val: staticAnalysis.hashes.ssdeep },
          ].map((h, i) => (
            <div 
              key={i} 
              className="bg-slate-950/80 p-3.5 rounded-2xl border border-white/[0.05] flex items-center justify-between gap-3 group hover:border-cyan-500/40 transition shadow-sm"
            >
              <div className="truncate">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-sans font-bold mb-0.5">
                  {h.label}
                </span>
                <span className="text-slate-300 text-xs truncate block select-all group-hover:text-cyan-300 transition">
                  {h.val}
                </span>
              </div>
              <button
                onClick={() => copyToClipboard(h.val, h.label)}
                className="p-2 bg-slate-900 hover:bg-cyan-500 hover:text-slate-950 text-slate-400 rounded-xl transition shrink-0 border border-white/[0.06]"
                title="Copy hash to clipboard"
              >
                {copiedHash === h.label ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Section Entropy & Structure */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Entropy Chart */}
        <div className="glass-card p-6 rounded-3xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" /> Section Shannon Entropy Curve
              </h3>
              <p className="text-xs text-slate-400">
                Values &gt; 7.0 indicate high randomness (packing, encryption, or compression)
              </p>
            </div>
            {staticAnalysis.pe_structure.is_packed && (
              <span className="px-2.5 py-1 text-[10px] font-bold uppercase rounded-lg bg-rose-950/90 text-rose-300 border border-rose-800 animate-pulse">
                Packed / Encrypted
              </span>
            )}
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={entropyData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="entropyGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} fontStyle="monospace" />
                <YAxis domain={[0, 8]} stroke="#64748b" fontSize={11} fontStyle="monospace" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#030712', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }}
                  formatter={(val: any) => [`${val} / 8.0`, 'Entropy']}
                />
                <Area type="monotone" dataKey="entropy" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#entropyGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 pt-3 border-t border-white/[0.06] text-xs text-slate-400 flex items-center justify-between font-mono">
            <span>Overall File Entropy: <strong className="text-cyan-300">{staticAnalysis.file_info.entropy}</strong></span>
            <span>Packer: <span className="text-amber-300">{staticAnalysis.pe_structure.packer || "None Detected"}</span></span>
          </div>
        </div>

        {/* Suspicious Win32 APIs */}
        <div className="glass-card p-6 rounded-3xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" /> High-Risk Imported Win32 APIs
                </h3>
                <p className="text-xs text-slate-400">
                  APIs associated with process injection, evasion, and persistence
                </p>
              </div>
              <span className="text-xs font-mono font-bold text-rose-300 bg-rose-950/80 px-2.5 py-1 rounded-lg border border-rose-800">
                {staticAnalysis.pe_structure.import_count} Flagged
              </span>
            </div>

            <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
              {staticAnalysis.pe_structure.imports.length > 0 ? (
                staticAnalysis.pe_structure.imports.map((api, idx) => (
                  <div key={idx} className="p-3 bg-slate-950/80 rounded-xl border border-white/[0.05] flex items-start justify-between gap-3 text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-white text-xs">{api.function}</span>
                        <span className="text-[10px] text-slate-500 font-mono">[{api.dll}]</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{api.description}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                      api.risk === 'HIGH' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}>
                      {api.risk}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic text-center py-6">
                  No known high-risk API imports identified in binary table.
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-white/[0.06] text-xs text-slate-400 flex items-center justify-between">
            <span>Digital Certificate</span>
            <span className="text-rose-400 font-mono font-bold text-[11px]">
              {staticAnalysis.pe_structure.digital_signature.status}
            </span>
          </div>
        </div>
      </div>

      {/* Extracted Forensic Strings & Auto-Decoder */}
      <div className="glass-card p-6 rounded-3xl">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
          <div>
            <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
              <Binary className="w-4 h-4 text-cyan-400" /> Extracted Strings &amp; Auto-Decoded Streams
            </h3>
            <p className="text-xs text-slate-400">
              Recovered ASCII, UTF-16LE Unicode, Base64, and XOR decoded telemetry
            </p>
          </div>

          {/* Search bar & tab filters */}
          <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-48">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={stringFilter}
                onChange={e => setStringFilter(e.target.value)}
                placeholder="Filter strings..."
                className="w-full bg-slate-950 border border-white/[0.08] rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
              />
            </div>

            <div className="flex rounded-xl bg-slate-950 p-1 border border-white/[0.08] text-xs font-bold font-mono">
              <button
                onClick={() => setStringTab('decoded')}
                className={`px-3 py-1 rounded-lg transition ${stringTab === 'decoded' ? 'bg-cyan-500 text-slate-950 font-black' : 'text-slate-400 hover:text-white'}`}
              >
                Decoded ({staticAnalysis.strings.decoded.length})
              </button>
              <button
                onClick={() => setStringTab('ascii')}
                className={`px-3 py-1 rounded-lg transition ${stringTab === 'ascii' ? 'bg-cyan-500 text-slate-950 font-black' : 'text-slate-400 hover:text-white'}`}
              >
                ASCII ({staticAnalysis.strings.ascii_total})
              </button>
              <button
                onClick={() => setStringTab('unicode')}
                className={`px-3 py-1 rounded-lg transition ${stringTab === 'unicode' ? 'bg-cyan-500 text-slate-950 font-black' : 'text-slate-400 hover:text-white'}`}
              >
                Unicode ({staticAnalysis.strings.unicode_total})
              </button>
            </div>
          </div>
        </div>

        {/* Content list */}
        <div className="bg-slate-950/90 rounded-2xl border border-white/[0.06] p-3 max-h-72 overflow-y-auto font-mono text-xs">
          {stringTab === 'decoded' && (
            <div className="space-y-2">
              {filteredDecoded.length > 0 ? (
                filteredDecoded.map((s, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-900/80 rounded-xl border border-white/[0.05] flex items-center justify-between gap-3">
                    <div className="truncate">
                      <span className="text-[10px] uppercase font-bold text-purple-400 block">{s.type}</span>
                      <span className="text-cyan-300 font-bold text-xs select-all">{s.decoded}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 truncate max-w-[120px]">{s.original}</span>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic text-center py-6">No decoded obfuscated strings matched the filter.</div>
              )}
            </div>
          )}

          {stringTab === 'ascii' && (
            <div className="space-y-1">
              {filteredAscii.length > 0 ? (
                filteredAscii.map((s, idx) => (
                  <div key={idx} className="py-1 px-2 hover:bg-slate-900 rounded text-slate-300 select-all truncate border-b border-slate-900/50">
                    {s}
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic text-center py-6">No ASCII strings found matching filter.</div>
              )}
            </div>
          )}

          {stringTab === 'unicode' && (
            <div className="space-y-1">
              {filteredUnicode.length > 0 ? (
                filteredUnicode.map((s, idx) => (
                  <div key={idx} className="py-1 px-2 hover:bg-slate-900 rounded text-sky-300 select-all truncate border-b border-slate-900/50">
                    {s}
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic text-center py-6">No Unicode strings found matching filter.</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
