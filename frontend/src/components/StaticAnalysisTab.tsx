import React, { useState } from 'react';
import { StaticAnalysis } from '../types';
import { SectionGuide } from './SectionGuide';
import { Copy, Check, FileCode, Cpu, Code2, Search, Lock, Binary, ShieldAlert } from 'lucide-react';
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
        title="Static Malware Analysis &amp; Structural Disassembly"
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

      {/* File Hashes Card */}
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
        <h3 className="text-base font-bold text-slate-200 mb-4 flex items-center gap-2">
          <FileCode className="w-4 h-4 text-cyan-400" /> Cryptographic File Hashes
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
          {[
            { label: 'MD5', val: staticAnalysis.hashes.md5 },
            { label: 'SHA1', val: staticAnalysis.hashes.sha1 },
            { label: 'SHA256', val: staticAnalysis.hashes.sha256 },
            { label: 'SSDEEP', val: staticAnalysis.hashes.ssdeep },
          ].map(item => (
            <div key={item.label} className="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div className="truncate mr-2">
                <span className="text-slate-400 font-bold block mb-0.5">{item.label}</span>
                <span className="text-cyan-300 truncate">{item.val}</span>
              </div>
              <button
                onClick={() => copyToClipboard(item.val, item.label)}
                className="p-1.5 text-slate-400 hover:text-white bg-slate-800 rounded transition"
                title="Copy hash"
              >
                {copiedHash === item.label ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* PE Header & Section Entropy Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
          <h3 className="text-base font-bold text-slate-200 mb-2 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" /> Section Entropy Profile
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Entropy values &gt; 7.0 indicate packed or encrypted sections (e.g., UPX, Themida).
          </p>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={entropyData}>
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 8]} stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} />
                <Area type="monotone" dataKey="entropy" stroke="#a855f7" fill="#a855f722" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between text-xs text-slate-400">
            <span>Packer Detection: <strong className="text-amber-400">{staticAnalysis.pe_structure.packer || 'None Detected'}</strong></span>
            <span>Digital Signature: <strong className="text-rose-400">{staticAnalysis.pe_structure.digital_signature.status}</strong></span>
          </div>
        </div>

        {/* Suspicious API Imports Table */}
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl flex flex-col">
          <h3 className="text-base font-bold text-slate-200 mb-4 flex items-center gap-2">
            <Code2 className="w-4 h-4 text-cyan-400" /> Suspicious Imported APIs ({staticAnalysis.pe_structure.import_count})
          </h3>

          <div className="overflow-y-auto max-h-64 flex-1 space-y-2 pr-1">
            {staticAnalysis.pe_structure.imports.length === 0 ? (
              <div className="text-slate-500 text-xs italic py-4 text-center">No high-risk Windows API functions imported.</div>
            ) : (
              staticAnalysis.pe_structure.imports.map((imp, idx) => (
                <div key={idx} className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800 text-xs flex items-center justify-between">
                  <div>
                    <span className="font-mono text-cyan-300 font-bold">{imp.function}</span>
                    <span className="text-slate-500 ml-2">({imp.dll})</span>
                    <div className="text-slate-400 mt-0.5">{imp.description}</div>
                  </div>
                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${imp.risk === 'HIGH' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}`}>
                    {imp.risk}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* String Extraction & Auto-Decoders Card */}
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" /> Extracted & Decoded Strings
          </h3>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={stringFilter}
                onChange={e => setStringFilter(e.target.value)}
                placeholder="Filter strings..."
                className="w-full bg-slate-950 border border-slate-800 text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              <button
                onClick={() => setStringTab('decoded')}
                className={`px-3 py-1 rounded font-medium ${stringTab === 'decoded' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
              >
                Decoded ({staticAnalysis.strings.decoded.length})
              </button>
              <button
                onClick={() => setStringTab('ascii')}
                className={`px-3 py-1 rounded font-medium ${stringTab === 'ascii' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
              >
                ASCII ({staticAnalysis.strings.ascii_total})
              </button>
              <button
                onClick={() => setStringTab('unicode')}
                className={`px-3 py-1 rounded font-medium ${stringTab === 'unicode' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
              >
                Unicode ({staticAnalysis.strings.unicode_total})
              </button>
            </div>
          </div>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs max-h-64 overflow-y-auto space-y-1.5">
          {stringTab === 'decoded' && (
            filteredDecoded.length === 0 ? (
              <div className="text-slate-500 italic py-2">No matching decoded string artifacts.</div>
            ) : (
              filteredDecoded.map((item, idx) => (
                <div key={idx} className="bg-slate-900/90 p-2 rounded border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="text-amber-400 font-semibold mr-2">[{item.type}]</span>
                    <span className="text-cyan-300 font-bold">{item.decoded}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 truncate max-w-[200px]">Raw: {item.original}</span>
                </div>
              ))
            )
          )}

          {stringTab === 'ascii' && (
            filteredAscii.slice(0, 100).map((str, idx) => (
              <div key={idx} className="text-slate-300 hover:text-cyan-300 py-0.5 border-b border-slate-900/50 truncate">
                {str}
              </div>
            ))
          )}

          {stringTab === 'unicode' && (
            filteredUnicode.slice(0, 50).map((str, idx) => (
              <div key={idx} className="text-purple-300 hover:text-cyan-300 py-0.5 border-b border-slate-900/50 truncate">
                {str}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
