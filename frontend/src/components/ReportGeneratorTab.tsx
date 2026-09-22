import React, { useState, useEffect } from 'react';
import { FullAnalysisReport } from '../types';
import { SectionGuide } from './SectionGuide';
import { FileText, Download, Printer, Copy, Check, ExternalLink, ShieldCheck, Award, Share2 } from 'lucide-react';

interface Props {
  report: FullAnalysisReport;
}

export const ReportGeneratorTab: React.FC<Props> = ({ report }) => {
  const [reportFormat, setReportFormat] = useState<'html' | 'markdown' | 'stix'>('html');
  const [htmlContent, setHtmlContent] = useState<string>('');
  const [markdownContent, setMarkdownContent] = useState<string>('');
  const [copiedMd, setCopiedMd] = useState(false);

  const generateClientMarkdown = () => {
    let md = `# Pasha - Malware Analysis Report\n`;
    md += `**Sample Target:** \`${report.sample_name}\`\n`;
    md += `**Analysis Date:** ${report.timestamp.split('T')[0]}\n`;
    md += `**Threat Score:** ${report.threat_scoring.threat_score}/100 (**${report.threat_scoring.verdict}**)\n\n---\n\n`;
    md += `## 1. Executive Summary\n- Verdict: ${report.threat_scoring.verdict}\n- Severity: ${report.threat_scoring.severity}\n- Entropy: ${report.static_analysis.file_info.entropy}\n\n`;
    md += `## 2. Cryptographic Hashes\n- SHA-256: \`${report.static_analysis.hashes.sha256}\`\n- MD5: \`${report.static_analysis.hashes.md5}\`\n\n`;
    md += `## 3. Extracted IOCs (${report.ioc_extraction.total_extracted})\n`;
    report.ioc_extraction.iocs.forEach(i => {
      md += `- [${i.type}] \`${i.value}\` (${i.category})\n`;
    });
    return md;
  };

  const generateClientHtml = () => {
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Pasha - ${report.sample_name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #080502; color: #f8fafc; padding: 30px; line-height: 1.6; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #7c2d12; padding-bottom: 20px; margin-bottom: 30px; }
    .badge { background: ${report.threat_scoring.color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 1.1em; }
    .card { background: #140c07; border-radius: 12px; padding: 20px; margin-bottom: 25px; border: 1px solid #7c2d12; }
    h1 { color: #ffffff; margin: 0; }
    h2 { color: #f97316; margin-top: 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #431407; }
    th { background: #0f0804; color: #fdba74; }
    code { background: #1c0d06; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #fb923c; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>Pasha - Analysis Report</h1>
      <p style="color: #fdba74">Target Sample: <strong>${report.sample_name}</strong> | Generated: ${report.timestamp.split('T')[0]}</p>
    </div>
    <div class="badge">${report.threat_scoring.threat_score}/100 - ${report.threat_scoring.verdict}</div>
  </div>
  <div class="card">
    <h2>Executive File Metadata</h2>
    <p><strong>File Type:</strong> ${report.static_analysis.file_info.type}</p>
    <p><strong>Entropy:</strong> ${report.static_analysis.file_info.entropy} | <strong>MD5:</strong> <code>${report.static_analysis.hashes.md5}</code></p>
    <p><strong>SHA256:</strong> <code>${report.static_analysis.hashes.sha256}</code></p>
  </div>
  <div class="card">
    <h2>YARA Signature Matches (${report.yara_scan.match_count})</h2>
    <table>
      <tr><th>Rule Name</th><th>Severity</th><th>Description</th></tr>
      ${report.yara_scan.matches.map(m => `<tr><td><code>${m.rule_name}</code></td><td>${m.severity}</td><td>${m.description}</td></tr>`).join('')}
    </table>
  </div>
  <div class="card">
    <h2>Extracted Indicators of Compromise (${report.ioc_extraction.total_extracted})</h2>
    <table>
      <tr><th>Type</th><th>Value</th><th>Category</th></tr>
      ${report.ioc_extraction.iocs.map(i => `<tr><td>${i.type}</td><td><code>${i.value}</code></td><td>${i.category}</td></tr>`).join('')}
    </table>
  </div>
</body>
</html>`;
  };

  useEffect(() => {
    // Attempt fetch from backend, fallback to client generator
    fetch(`/api/reports/${report.report_id}/export/html`)
      .then(res => {
        if (!res.ok) throw new Error("Backend offline");
        return res.text();
      })
      .then(html => setHtmlContent(html))
      .catch(() => setHtmlContent(generateClientHtml()));

    fetch(`/api/reports/${report.report_id}/export/markdown`)
      .then(res => {
        if (!res.ok) throw new Error("Backend offline");
        return res.text();
      })
      .then(md => setMarkdownContent(md))
      .catch(() => setMarkdownContent(generateClientMarkdown()));
  }, [report]);

  const handlePrintPdf = () => {
    const content = htmlContent || generateClientHtml();
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(content);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    }
  };

  const downloadHtmlReport = () => {
    const content = htmlContent || generateClientHtml();
    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.sample_name}_threat_report.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    const content = markdownContent || generateClientMarkdown();
    navigator.clipboard.writeText(content);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="Automated Executive &amp; Technical Reporting Engine"
        badge="Audit &amp; Compliance"
        whatItDoes="Synthesizes all analytical telemetry into publication-ready formats: Responsive HTML Executive Reports, formatted Markdown summaries, STIX 2.1 CTI bundles, and print-ready PDF exports. Each report captures sample metadata, threat scores, YARA signature detections, extracted IOC tables, and MITRE ATT&CK TTP mappings."
        howItHelps="Transforms complex reverse engineering data into clear, defensible artifacts for management briefings, legal chain of custody, customer security audits, and regulatory compliance. You can save the report as PDF or paste the Markdown directly into Jira, GitHub issues, or Slack."
        keyIndicators={[
          { label: "Executive Summary", detail: "High-level risk rating and verdict designed for CISO and leadership briefings", severity: "info" },
          { label: "Cryptographic Provenance", detail: "Immutable SHA256 and MD5 hashes establishing forensically sound chain of custody", severity: "info" },
          { label: "STIX 2.1 Bundle Export", detail: "Directly importable into Threat Intelligence Platforms (TIP) like OpenCTI and ThreatConnect", severity: "info" },
          { label: "Printable PDF Mode", detail: "Clean print styling formatted for offline distribution or incident archive storage", severity: "info" }
        ]}
        analystTip="Click 'Print / Save as PDF' in the top right corner to generate an offline PDF report with professional typography."
        defaultExpanded={false}
      />

      {/* Header Bar */}
      <div className="glass-panel p-6 rounded-3xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-extrabold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-orange-400" /> Executive &amp; Technical Threat Dossier
            </h3>
            <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-md bg-orange-950/80 text-orange-300 border border-orange-800/60">
              CISO Ready
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Publication-ready compliance reporting with cryptographic verification chain of custody
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handlePrintPdf}
            className="flex items-center gap-1.5 px-4 py-2.5 bg-gradient-to-r from-orange-600 via-amber-600 to-orange-500 hover:from-orange-500 hover:to-orange-400 text-white font-black rounded-xl text-xs transition shadow-lg shadow-orange-950/50"
          >
            <Printer className="w-4 h-4" /> Print / Save as PDF
          </button>
          <button
            onClick={downloadHtmlReport}
            className="flex items-center gap-1.5 px-3.5 py-2.5 bg-slate-900/90 hover:bg-slate-800 text-slate-200 hover:text-white rounded-xl text-xs font-bold border border-white/[0.08] transition shadow-sm cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" /> HTML Dossier
          </button>
        </div>
      </div>

      {/* Format Selector Pills */}
      <div className="flex gap-2">
        {[
          { id: 'html', label: 'Interactive HTML View', icon: FileText },
          { id: 'markdown', label: 'Markdown Format (Jira / GitHub)', icon: Copy },
        ].map(fmt => (
          <button
            key={fmt.id}
            onClick={() => setReportFormat(fmt.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition font-mono ${
              reportFormat === fmt.id
                ? 'bg-gradient-to-r from-orange-600 via-amber-600 to-orange-500 text-white font-black shadow-md shadow-orange-950/40'
                : 'glass-card text-slate-400 hover:text-white'
            }`}
          >
            <fmt.icon className="w-3.5 h-3.5" />
            {fmt.label}
          </button>
        ))}
      </div>

      {/* Viewport: HTML Preview */}
      {reportFormat === 'html' && (
        <div className="glass-card rounded-3xl overflow-hidden border border-white/[0.08] shadow-2xl">
          <div className="bg-slate-950/80 px-4 py-2 border-b border-white/[0.06] flex justify-between items-center text-xs text-slate-400 font-mono">
            <span>PREVIEW: Responsive Executive Report</span>
            <span className="text-emerald-400 font-bold">&bull; Live Rendering</span>
          </div>
          <iframe
            srcDoc={htmlContent}
            title="Executive Report HTML Preview"
            className="w-full h-[650px] bg-white border-none"
          />
        </div>
      )}

      {/* Viewport: Markdown Preview */}
      {reportFormat === 'markdown' && (
        <div className="glass-card rounded-3xl p-6 border border-white/[0.08] space-y-3">
          <div className="flex justify-between items-center">
            <span className="text-xs font-bold text-slate-300 uppercase font-mono">
              Markdown Source Code (Copy for Incident Tickets)
            </span>
            <button
              onClick={copyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-orange-600 via-amber-600 to-orange-500 hover:from-orange-500 hover:to-orange-400 text-white font-black rounded-lg text-xs transition shadow-md shadow-orange-950/40"
            >
              {copiedMd ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedMd ? "Copied to Clipboard!" : "Copy Markdown"}
            </button>
          </div>
          <pre className="p-4 bg-slate-950/90 rounded-2xl border border-white/[0.06] text-slate-300 font-mono text-xs max-h-[550px] overflow-y-auto whitespace-pre-wrap select-all">
            {markdownContent}
          </pre>
        </div>
      )}
    </div>
  );
};
