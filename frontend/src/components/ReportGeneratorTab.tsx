import React, { useState, useEffect } from 'react';
import { FullAnalysisReport } from '../types';
import { SectionGuide } from './SectionGuide';
import { FileText, Download, Printer, Copy, Check, ExternalLink, ShieldCheck, Award } from 'lucide-react';

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
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" /> Automated Malware Analysis Report Generator
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Executive Summary, Static/Behavioral Breakdown, ATT&CK Matrix, IOC list, and PDF/HTML/STIX 2.1 Export.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setReportFormat('html')}
              className={`px-3 py-1 rounded font-semibold ${reportFormat === 'html' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
            >
              HTML Executive
            </button>
            <button
              onClick={() => setReportFormat('markdown')}
              className={`px-3 py-1 rounded font-semibold ${reportFormat === 'markdown' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
            >
              Markdown
            </button>
            <button
              onClick={() => setReportFormat('stix')}
              className={`px-3 py-1 rounded font-semibold ${reportFormat === 'stix' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'}`}
            >
              STIX 2.1 Bundle
            </button>
          </div>

          <button
            onClick={handlePrintPdf}
            className="flex items-center gap-1.5 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-semibold text-xs transition shadow-lg"
          >
            <Printer className="w-4 h-4" /> Print / Save as PDF
          </button>
        </div>
      </div>

      {/* Live Preview Document Frame */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        {reportFormat === 'html' && (
          <iframe
            title="Executive HTML Report Preview"
            srcDoc={htmlContent}
            className="w-full h-[650px] border-none bg-slate-950"
          />
        )}

        {reportFormat === 'markdown' && (
          <div className="p-5 font-mono text-xs text-slate-300 max-h-[650px] overflow-y-auto space-y-4">
            <div className="flex justify-between items-center pb-3 border-b border-slate-800">
              <span className="text-slate-400 font-bold">Markdown Source Output</span>
              <button
                onClick={copyMarkdown}
                className="flex items-center gap-1 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs"
              >
                {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedMd ? 'Copied!' : 'Copy Markdown'}
              </button>
            </div>
            <pre className="whitespace-pre-wrap bg-slate-950 p-4 rounded border border-slate-800 text-cyan-300">
              {markdownContent}
            </pre>
          </div>
        )}

        {reportFormat === 'stix' && (
          <div className="p-5 font-mono text-xs text-slate-300 max-h-[650px] overflow-y-auto">
            <div className="mb-3 text-slate-400 font-bold">STIX 2.1 Cyber Threat Intelligence JSON Bundle</div>
            <pre className="whitespace-pre-wrap bg-slate-950 p-4 rounded border border-slate-800 text-emerald-300">
              {JSON.stringify({
                type: "bundle",
                id: `bundle--${report.report_id.slice(0, 36)}`,
                spec_version: "2.1",
                objects: [
                  {
                    type: "malware",
                    name: report.sample_name,
                    threat_score: report.threat_scoring.threat_score,
                    verdict: report.threat_scoring.verdict
                  },
                  ...report.ioc_extraction.iocs.map(i => ({
                    type: "indicator",
                    pattern: `[${i.type} = '${i.value}']`
                  }))
                ]
              }, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
