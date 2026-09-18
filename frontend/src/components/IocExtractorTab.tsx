import React, { useState } from 'react';
import { IocExtraction } from '../types';
import { SectionGuide } from './SectionGuide';
import { Database, Download, Copy, Check, ShieldAlert, Globe, Key, FileText, Share2, Search, Filter } from 'lucide-react';

interface Props {
  ioc: IocExtraction;
  reportId: string;
}

export const IocExtractorTab: React.FC<Props> = ({ ioc, reportId }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const filteredIocs = ioc.iocs.filter(item => {
    const matchesCat = categoryFilter === 'ALL' || item.category.toLowerCase().includes(categoryFilter.toLowerCase()) || item.type.toLowerCase().includes(categoryFilter.toLowerCase());
    const matchesSearch = item.value.toLowerCase().includes(searchQuery.toLowerCase()) || item.type.toLowerCase().includes(searchQuery.toLowerCase()) || item.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const exportCsv = () => {
    let csv = "Type,Value,Category,Confidence,Risk\n";
    ioc.iocs.forEach(i => {
      csv += `"${i.type}","${i.value}","${i.category}",${i.confidence},"${i.threat_intel?.risk || 'HIGH'}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'extracted_iocs.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadStix = async () => {
    window.open(`/api/reports/${reportId}/export/stix`, '_blank');
  };

  const downloadMisp = async () => {
    window.open(`/api/reports/${reportId}/export/misp`, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="Automated IOC Extraction &amp; Threat Intel Sharing"
        badge="Threat Intelligence"
        whatItDoes="Automatically extracts Indicators of Compromise (IOCs) across multiple dimensions: Cryptographic File Hashes (MD5, SHA256), Network Command-and-Control IPs, Domains, URLs, Windows Registry persistence keys, Dropped file paths, and Ransomware Crypto Wallets (Bitcoin, Ethereum). It formats indicators into industry standard STIX 2.1 and MISP JSON schemas."
        howItHelps="Extracted IOCs provide actionable artifacts you can immediately feed into perimeter firewalls (Palo Alto, Fortinet), DNS sinkholes, Endpoint Detection &amp; Response (EDR) blocklists (CrowdStrike, SentinelOne), and SIEM search rules (Splunk, Elastic) to contain attacks across your network."
        keyIndicators={[
          { label: "Network C2 IPs/Domains", detail: "Active IP addresses and domains receiving beacon telemetry or downloading second-stage payloads", severity: "critical" },
          { label: "Crypto Wallets (BTC/ETH)", detail: "Payment addresses embedded in ransom notes or crypto drainers; indicates active ransomware campaigns", severity: "critical" },
          { label: "Registry Persistence Keys", detail: "Exact RunKey registry values that need deletion during incident eradication", severity: "high" },
          { label: "Dropped Artifact Paths", detail: "File paths in AppData or Temp that need automated host quarantine", severity: "high" },
          { label: "STIX 2.1 &amp; MISP Feeds", detail: "Standardized machine-readable threat sharing formats used by global ISACs and SOCs", severity: "info" }
        ]}
        analystTip="Use the 'STIX 2.1 JSON' button above to export structured threat bundles that can be ingested into your organization's OpenCTI or MISP threat intelligence platforms."
        defaultExpanded={false}
      />

      {/* Header Controls */}
      <div className="glass-panel p-6 rounded-3xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-extrabold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-purple-400" /> Extracted Indicators of Compromise (IOCs)
            </h3>
            <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-md bg-purple-950/80 text-purple-300 border border-purple-800">
              {ioc.total_extracted} Indicators
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Machine-readable forensic artifacts for firewall rules, EDR blocklists, and threat hunting feeds
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-900/90 hover:bg-slate-800 text-slate-200 hover:text-white rounded-xl text-xs font-bold border border-white/[0.08] transition shadow-sm"
          >
            <Download className="w-3.5 h-3.5" /> CSV Table
          </button>
          <button
            onClick={downloadStix}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-cyan-600 to-sky-600 hover:from-cyan-500 hover:to-sky-500 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-cyan-900/30"
          >
            <Share2 className="w-3.5 h-3.5" /> STIX 2.1 JSON
          </button>
          <button
            onClick={downloadMisp}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-purple-900/30"
          >
            <Share2 className="w-3.5 h-3.5" /> MISP Feed
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-card p-4 rounded-2xl flex flex-col sm:flex-row justify-between items-center gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search indicator values..."
            className="w-full bg-slate-950 border border-white/[0.08] rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
          />
        </div>

        <div className="flex flex-wrap gap-1.5 w-full sm:w-auto">
          {['ALL', 'Network', 'File', 'Persistence', 'Crypto'].map(cat => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold transition ${
                categoryFilter === cat 
                  ? 'bg-cyan-500 text-slate-950 font-black shadow-md' 
                  : 'bg-slate-950 text-slate-400 hover:text-white border border-white/[0.06]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* IOC Grid Table */}
      <div className="glass-card rounded-3xl overflow-hidden border border-white/[0.06]">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-white/[0.06]">
              <tr>
                <th className="p-3.5">Type &amp; Category</th>
                <th className="p-3.5">Indicator Value</th>
                <th className="p-3.5">Confidence</th>
                <th className="p-3.5">Risk Rating</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04] bg-slate-950/40">
              {filteredIocs.length > 0 ? (
                filteredIocs.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/60 transition">
                    <td className="p-3.5">
                      <span className="text-white font-bold block">{item.type}</span>
                      <span className="text-[10px] text-slate-500">{item.category}</span>
                    </td>
                    <td className="p-3.5">
                      <span className="text-cyan-300 font-bold select-all break-all">{item.value}</span>
                      {item.threat_intel?.virustotal_ratio && (
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          VT: <span className="text-rose-400">{item.threat_intel.virustotal_ratio}</span>
                        </div>
                      )}
                    </td>
                    <td className="p-3.5">
                      <span className="px-2 py-0.5 rounded-md bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 text-[10px] font-bold">
                        {item.confidence}%
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold ${
                        item.threat_intel?.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        item.threat_intel?.risk === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {item.threat_intel?.risk || 'HIGH'}
                      </span>
                    </td>
                    <td className="p-3.5 text-right">
                      <button
                        onClick={() => copyToClipboard(item.value, idx)}
                        className="p-1.5 bg-slate-900 hover:bg-cyan-500 hover:text-slate-950 text-slate-400 rounded-xl transition border border-white/[0.06]"
                        title="Copy Indicator Value"
                      >
                        {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 italic">
                    No Indicators of Compromise found matching current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
