import React, { useState } from 'react';
import { IocExtraction } from '../types';
import { Database, Download, Copy, Check, ShieldAlert, Globe, Key, FileText } from 'lucide-react';

interface Props {
  ioc: IocExtraction;
  reportId: string;
}

export const IocExtractorTab: React.FC<Props> = ({ ioc, reportId }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const filteredIocs = ioc.iocs.filter(item => {
    if (categoryFilter === 'ALL') return true;
    return item.category.toLowerCase().includes(categoryFilter.toLowerCase()) || item.type.toLowerCase().includes(categoryFilter.toLowerCase());
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
      {/* Header Controls */}
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <Database className="w-5 h-5 text-emerald-400" /> Extracted Indicators of Compromise (IOCs)
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Automated Regex & Heuristic Extraction of Network, Host, Hash, and Crypto Artifacts ({ioc.total_extracted} Total).
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={downloadStix}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold rounded-lg transition"
          >
            <Download className="w-3.5 h-3.5" /> STIX 2.1 JSON
          </button>
          <button
            onClick={downloadMisp}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold rounded-lg transition"
          >
            <Download className="w-3.5 h-3.5" /> MISP JSON
          </button>
          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>
        </div>
      </div>

      {/* Category Pills */}
      <div className="flex flex-wrap gap-2 text-xs">
        {['ALL', 'Network', 'File', 'Persistence', 'Crypto'].map(cat => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-3 py-1.5 rounded-lg border font-semibold transition ${
              categoryFilter === cat
                ? 'bg-emerald-500/20 border-emerald-500 text-emerald-300'
                : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            {cat} Filters
          </button>
        ))}
      </div>

      {/* IOC Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left font-mono text-xs">
          <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-3">Type</th>
              <th className="p-3">IOC Value</th>
              <th className="p-3">Category</th>
              <th className="p-3">Threat Intelligence Context</th>
              <th className="p-3">Confidence</th>
              <th className="p-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredIocs.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-6 text-center text-slate-500 italic">No indicators found matching filter.</td>
              </tr>
            ) : (
              filteredIocs.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40">
                  <td className="p-3 text-cyan-300 font-bold">{item.type}</td>
                  <td className="p-3 text-slate-200 font-bold break-all max-w-xs">{item.value}</td>
                  <td className="p-3 text-slate-400">{item.category}</td>
                  <td className="p-3 text-slate-400 text-[11px]">
                    {item.threat_intel?.virustotal_ratio && (
                      <span className="mr-2 text-rose-400">VT: {item.threat_intel.virustotal_ratio}</span>
                    )}
                    {item.threat_intel?.abuseipdb_score && (
                      <span className="mr-2 text-amber-400">AbuseIPDB: {item.threat_intel.abuseipdb_score}</span>
                    )}
                    {item.threat_intel?.risk && (
                      <span className="px-1.5 py-0.5 bg-rose-950 text-rose-300 border border-rose-800 rounded text-[10px] font-bold">
                        {item.threat_intel.risk}
                      </span>
                    )}
                  </td>
                  <td className="p-3">
                    <span className="text-emerald-400 font-bold">{item.confidence}%</span>
                  </td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => copyToClipboard(item.value, idx)}
                      className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                      title="Copy IOC value"
                    >
                      {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
