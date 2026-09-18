import React, { useState } from 'react';
import { MitreMapping, MitreTechnique } from '../types';
import { SectionGuide } from './SectionGuide';
import { Layers, ShieldAlert, Download, CheckCircle2, ExternalLink, Target, Flame, ChevronRight, X } from 'lucide-react';

interface Props {
  mitre: MitreMapping;
}

export const MitreAttackTab: React.FC<Props> = ({ mitre }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const downloadNavigatorJson = () => {
    const jsonStr = JSON.stringify(mitre.navigator_layer, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mitre_attack_navigator_layer.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Comprehensive Section Guide */}
      <SectionGuide
        title="MITRE ATT&amp;CK Matrix &amp; TTP Alignment"
        badge="Enterprise Threat Matrix"
        whatItDoes="Correlates every low-level indicator—suspicious API calls, modified registry RunKeys, YARA signatures, and network beacons—to standard MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK v14+) IDs. It groups findings into 12 core enterprise adversary tactics (Initial Access through Impact) and exports an ATT&CK Navigator JSON layer."
        howItHelps="Standardizes reporting so incident responders and threat hunters can map the adversary's playbook. Rather than seeing raw assembly calls, teams understand the threat's kill chain: 'T1059 Command Execution' &rarr; 'T1055 Process Injection' &rarr; 'T1547 Persistence' &rarr; 'T1490 Recovery Inhibition'."
        keyIndicators={[
          { label: "T1490 (Inhibit Recovery)", detail: "Signature of Ransomware deleting volume shadow copies (vssadmin/bcdedit)", severity: "critical" },
          { label: "T1055 (Process Injection)", detail: "Adversary injecting malicious code into notepad.exe or svchost.exe to bypass antivirus", severity: "critical" },
          { label: "T1555 (Credentials from Web Browsers)", detail: "Infostealers querying browser SQLite databases to exfiltrate passwords and cookies", severity: "critical" },
          { label: "T1071 (Application Layer Protocol)", detail: "C2 servers masking beacons as legitimate HTTPS traffic to bypass corporate firewalls", severity: "high" },
          { label: "T1547 (Boot/Logon Autostart)", detail: "Registry RunKeys and scheduled tasks established to survive host reboots", severity: "high" }
        ]}
        analystTip="Click on any highlighted technique pill in the 12-tactic board below to open the Evidence Drawer showing the exact API invocation and PID trigger."
        defaultExpanded={false}
      />

      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-3xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-extrabold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-400" /> MITRE ATT&amp;CK Enterprise Matrix (v14+)
            </h3>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded-md bg-purple-950/80 text-purple-300 border border-purple-800">
              {mitre.total_techniques_mapped} Techniques Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated low-level binary features, API traces, and YARA matches across enterprise adversary tactics
          </p>
        </div>

        <button
          onClick={downloadNavigatorJson}
          className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-xl font-bold text-xs transition shadow-lg shadow-purple-900/30 shrink-0"
        >
          <Download className="w-4 h-4" /> Export ATT&amp;CK Navigator Layer
        </button>
      </div>

      {/* Interactive 12-Tactic Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {mitre.tactics.map(tactic => {
          const techniquesForTactic = mitre.mapped_techniques.filter(
            t => t.tactic_name.toLowerCase() === tactic.name.toLowerCase()
          );

          const hasHits = techniquesForTactic.length > 0;

          return (
            <div
              key={tactic.id}
              className={`glass-card rounded-2xl p-3.5 flex flex-col justify-between transition min-h-[160px] ${
                hasHits
                  ? 'border-purple-500/50 bg-gradient-to-b from-purple-950/20 via-slate-900/60 to-slate-950/80 shadow-md shadow-purple-950/20'
                  : 'opacity-70 bg-slate-950/40'
              }`}
            >
              <div>
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="text-slate-500">{tactic.id}</span>
                  {hasHits && (
                    <span className="px-1.5 py-0.2 rounded font-bold bg-purple-500 text-slate-950">
                      {techniquesForTactic.length}
                    </span>
                  )}
                </div>

                <div className="text-xs font-bold text-white mb-2 leading-tight">
                  {tactic.name}
                </div>

                <div className="space-y-1.5">
                  {techniquesForTactic.map(tech => (
                    <button
                      key={tech.technique_id}
                      onClick={() => setSelectedTechnique(tech)}
                      className="w-full text-left p-1.5 rounded-lg bg-slate-900/90 hover:bg-purple-900/40 border border-purple-500/30 hover:border-purple-400 transition text-[11px] font-mono group"
                    >
                      <div className="text-purple-300 font-bold group-hover:text-white truncate">
                        {tech.technique_id}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate leading-tight mt-0.5">
                        {tech.name}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {!hasHits && (
                <div className="text-[10px] text-slate-600 italic mt-2">No active TTPs</div>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Technique Modal / Evidence Drawer */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fadeIn">
          <div className="glass-panel w-full max-w-lg rounded-3xl p-6 border border-purple-500/50 shadow-2xl space-y-4">
            <div className="flex justify-between items-start border-b border-white/[0.06] pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-mono font-bold rounded">
                    {selectedTechnique.technique_id}
                  </span>
                  <span className="text-xs uppercase font-bold text-slate-400">{selectedTechnique.tactic_name}</span>
                </div>
                <h4 className="text-base font-extrabold text-white mt-1">{selectedTechnique.name}</h4>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-slate-400 hover:text-white w-8 h-8 rounded-lg hover:bg-slate-800 flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {selectedTechnique.description}
            </p>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-white/[0.06] space-y-1 text-xs">
              <span className="text-[10px] text-slate-500 uppercase font-mono font-bold block">Telemetry Evidence</span>
              <div className="text-purple-300 font-mono text-[11px] break-all">{selectedTechnique.evidence}</div>
            </div>

            <div className="flex justify-between items-center text-xs pt-2">
              <a
                href={selectedTechnique.url}
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:underline flex items-center gap-1 font-mono text-[11px]"
              >
                View MITRE ATT&CK Matrix Docs <ExternalLink className="w-3 h-3" />
              </a>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-bold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
