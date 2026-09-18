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

  useEffect(() => {
    // Fetch HTML report preview
    fetch(`/api/reports/${report.report_id}/export/html`)
      .then(res => res.text())
      .then(html => setHtmlContent(html))
      .catch(() => {});

    // Fetch Markdown report preview
    fetch(`/api/reports/${report.report_id}/export/markdown`)
      .then(res => res.text())
      .then(md => setMarkdownContent(md))
      .catch(() => {});
  }, [report]);

  const handlePrintPdf = () => {
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(htmlContent);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    }
  };

  const copyMarkdown = () => {
    navigator.clipboard.writeText(markdownContent);
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
              <FileText className="w-5 h-5 text-rose-400" /> Executive &amp; Technical Threat Dossier
            </h3>
            <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-md bg-rose-950/80 text-rose-300 border border-rose-800">
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
            className="flex items-center gap-1.5 px-4 py-2.5 bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white font-black rounded-xl text-xs transition shadow-lg shadow-rose-900/30"
          >
            <Printer className="w-4 h-4" /> Print / Save as PDF
          </button>
          <a
            href={`/api/reports/${report.report_id}/export/html`}
            download={`${report.sample_name}_threat_report.html`}
            className="flex items-center gap-1.5 px-3.5 py-2.5 bg-slate-900/90 hover:bg-slate-800 text-slate-200 hover:text-white rounded-xl text-xs font-bold border border-white/[0.08] transition shadow-sm"
          >
            <Download className="w-3.5 h-3.5" /> HTML Dossier
          </a>
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
                ? 'bg-rose-600 text-white font-black shadow-md shadow-rose-950/40'
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
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-black rounded-lg text-xs transition"
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
