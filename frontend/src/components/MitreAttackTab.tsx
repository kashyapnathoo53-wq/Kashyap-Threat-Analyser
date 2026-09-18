import React, { useState } from 'react';
import { MitreMapping, MitreTechnique } from '../types';
import { SectionGuide } from './SectionGuide';
import { Layers, ShieldAlert, Download, CheckCircle2, ExternalLink, Target, Flame } from 'lucide-react';

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
      <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <Layers className="w-5 h-5 text-purple-400" /> MITRE ATT&CK Enterprise Matrix (v14+) Mapping
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Automated alignment of binary features, API calls, and YARA hits across the 12 core tactics.
          </p>
        </div>

        <button
          onClick={downloadNavigatorJson}
          className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-semibold text-xs transition shadow-lg"
        >
          <Download className="w-4 h-4" /> Download ATT&CK Navigator Layer
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
              className={`p-3 rounded-xl border transition-all min-h-[160px] flex flex-col ${
                hasHits
                  ? 'bg-slate-900/90 border-purple-500/60 shadow-lg'
                  : 'bg-slate-950/40 border-slate-800/80 opacity-60'
              }`}
            >
              <div className="text-[10px] font-mono text-purple-400 uppercase font-bold">{tactic.id}</div>
              <div className="text-xs font-bold text-slate-200 mb-2 truncate" title={tactic.name}>{tactic.name}</div>

              <div className="flex-1 space-y-1.5 overflow-y-auto">
                {techniquesForTactic.length === 0 ? (
                  <div className="text-[10px] text-slate-600 italic py-2">No active TTPs</div>
                ) : (
                  techniquesForTactic.map((t, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedTechnique(t)}
                      className={`w-full text-left p-1.5 rounded border text-[11px] font-mono transition ${
                        t.confidence === 'CRITICAL'
                          ? 'bg-rose-950/80 border-rose-500/60 text-rose-200 hover:border-rose-400'
                          : 'bg-purple-950/80 border-purple-500/60 text-purple-200 hover:border-purple-400'
                      }`}
                    >
                      <div className="font-bold">{t.technique_id}</div>
                      <div className="text-[10px] truncate">{t.technique_name}</div>
                    </button>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique Evidence Inspector */}
      {selectedTechnique && (
        <div className="bg-slate-900 border border-purple-500/50 p-5 rounded-xl shadow-2xl space-y-3">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h4 className="text-base font-bold text-white">
                {selectedTechnique.technique_id} - {selectedTechnique.technique_name}
              </h4>
            </div>
            <button
              onClick={() => setSelectedTechnique(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 bg-slate-800 rounded"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase font-bold block mb-1">Target Tactic</span>
              <span className="text-purple-300 font-bold">{selectedTechnique.tactic_name} ({selectedTechnique.tactic_id})</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase font-bold block mb-1">Confidence Rating</span>
              <span className="text-rose-400 font-bold">{selectedTechnique.confidence}</span>
            </div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-xs font-bold block mb-1">Runtime Execution Evidence:</span>
            <code className="text-cyan-300 text-xs font-mono block bg-slate-900 p-2 rounded border border-slate-800">
              {selectedTechnique.evidence}
            </code>
          </div>
        </div>
      )}
    </div>
  );
};
