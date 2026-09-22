// J.A.R.V.I.S. Tactical AI Voice Synthesis Engine (Iron Man Assistant)
// Powered by Web Speech API with procedural Stark sound synthesis

import { FullAnalysisReport, HostAssessment } from '../types';
import { cyberAudio } from './cyberAudio';

export interface JarvisSpeechState {
  isSpeaking: boolean;
  isPaused: boolean;
  currentText: string;
  activeTopic: 'full' | 'file' | 'system' | 'solution';
  currentWord: string;
  currentCharIndex: number;
}

class JarvisVoiceEngine {
  private synth: SpeechSynthesis | null = null;
  private currentUtterance: SpeechSynthesisUtterance | null = null;
  private voices: SpeechSynthesisVoice[] = [];
  private selectedVoice: SpeechSynthesisVoice | null = null;
  private rate: number = 1.0;
  private pitch: number = 0.93; // Slightly deeper, dignified British butler tone
  private listeners: ((state: JarvisSpeechState) => void)[] = [];

  private state: JarvisSpeechState = {
    isSpeaking: false,
    isPaused: false,
    currentText: '',
    activeTopic: 'full',
    currentWord: '',
    currentCharIndex: 0
  };

  constructor() {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      this.synth = window.speechSynthesis;
      this.initVoices();
      if (this.synth.onvoiceschanged !== undefined) {
        this.synth.onvoiceschanged = () => this.initVoices();
      }
    }
  }

  private initVoices() {
    if (!this.synth) return;
    this.voices = this.synth.getVoices();
    // Prioritize sophisticated British English voices (J.A.R.V.I.S. style)
    const britishVoices = this.voices.filter(v => 
      v.lang === 'en-GB' || 
      v.name.toLowerCase().includes('united kingdom') ||
      v.name.toLowerCase().includes('british') ||
      v.name.toLowerCase().includes('daniel') ||
      v.name.toLowerCase().includes('george') ||
      v.name.toLowerCase().includes('oliver') ||
      v.name.toLowerCase().includes('ryan') ||
      v.name.toLowerCase().includes('brian')
    );

    if (britishVoices.length > 0) {
      const preferred = britishVoices.find(v => 
        v.name.toLowerCase().includes('daniel') || 
        v.name.toLowerCase().includes('george') ||
        v.name.toLowerCase().includes('google uk english male')
      );
      this.selectedVoice = preferred || britishVoices[0];
    } else {
      const english = this.voices.filter(v => v.lang.startsWith('en'));
      this.selectedVoice = english.length > 0 ? english[0] : (this.voices[0] || null);
    }
  }

  public getAvailableVoices(): SpeechSynthesisVoice[] {
    if (this.voices.length === 0 && this.synth) {
      this.voices = this.synth.getVoices();
    }
    return this.voices.filter(v => v.lang.startsWith('en'));
  }

  public getSelectedVoice(): SpeechSynthesisVoice | null {
    return this.selectedVoice;
  }

  public setVoiceByName(voiceName: string) {
    const found = this.voices.find(v => v.name === voiceName);
    if (found) {
      this.selectedVoice = found;
    }
  }

  public setRate(rate: number) {
    this.rate = Math.max(0.7, Math.min(1.6, rate));
  }

  public getRate(): number {
    return this.rate;
  }

  public getState(): JarvisSpeechState {
    return { ...this.state };
  }

  public subscribe(listener: (state: JarvisSpeechState) => void): () => void {
    this.listeners.push(listener);
    listener(this.getState());
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notify() {
    this.listeners.forEach(l => l(this.getState()));
  }

  // Play Stark comms beep before speaking
  private playStarkChirp() {
    cyberAudio.playRadarSweep();
  }

  // 1. Generate Full Comprehensive Briefing
  public generateFullScript(report: FullAnalysisReport | null, host: HostAssessment | null): string {
    const parts: string[] = [];

    parts.push("Good day, sir. J.A.R.V.I.S. threat assessment online. I have completed a dual telemetry audit of both the submitted payload and your local host environment.");

    // Section A: File Analysis
    if (report) {
      const score = report.threat_scoring.threat_score;
      const severity = report.threat_scoring.severity;
      const verdict = report.threat_scoring.verdict;
      const sample = report.sample_name;

      parts.push(`First, regarding the suspicious file, ${sample}. My forensic engines categorize this binary with a threat score of ${score} out of 100, designated as a ${severity} severity ${verdict}.`);

      if (report.threat_scoring.risk_factors && report.threat_scoring.risk_factors.length > 0) {
        const topRisks = report.threat_scoring.risk_factors.slice(0, 3).join(". Furthermore, ");
        parts.push(`Critical indicators identified include: ${topRisks}.`);
      }

      if (report.yara_scan && report.yara_scan.matches && report.yara_scan.matches.length > 0) {
        const ruleNames = report.yara_scan.matches.slice(0, 2).map(m => m.rule_name.replace(/_/g, ' ')).join(" and ");
        parts.push(`YARA pattern heuristics triggered signatures for ${ruleNames}.`);
      }

      if (report.ioc_extraction && report.ioc_extraction.total_extracted > 0) {
        parts.push(`Our forensic pipeline intercepted ${report.ioc_extraction.total_extracted} indicators of compromise, including unauthorized command and control communication channels.`);
      }
    } else {
      parts.push("No active payload has been submitted for sandboxing at this moment.");
    }

    // Section B: Host System Analysis
    if (host) {
      const hostname = host.host_info.hostname;
      const health = host.health_score;
      const alert = host.alert_level;

      parts.push(`Turning now to your local host, machine name ${hostname}. Endpoint health is currently measured at ${health} out of 100, operating under an ${alert} alert level.`);

      const suspProcs = host.active_threats.filter(t => t.is_suspicious);
      if (suspProcs.length > 0) {
        const procDetails = suspProcs.slice(0, 2).map(p => `process ${p.name}, process ID ${p.pid}, exhibiting ${p.anomaly_reason}`).join(". In addition, ");
        parts.push(`Warning, sir: anomalous activity detected in ${suspProcs.length} host processes, specifically: ${procDetails}.`);
      } else {
        parts.push("Local background processes appear within normal operational tolerances.");
      }

      if (host.software_audit && host.software_audit.vulnerabilities && host.software_audit.vulnerabilities.length > 0) {
        const cveCount = host.software_audit.vulnerability_count;
        const topCve = host.software_audit.vulnerabilities[0];
        parts.push(`The software audit has uncovered ${cveCount} known CVE vulnerabilities, notably ${topCve.cve} in ${topCve.software}, carrying a CVSS severity of ${topCve.cvss}.`);
      }
    }

    // Section C: Remediation Protocol
    parts.push("Here is our recommended tactical mitigation protocol, sir.");
    if (host && host.remediation_plan && host.remediation_plan.length > 0) {
      host.remediation_plan.slice(0, 3).forEach((item, idx) => {
        parts.push(`Action ${idx + 1}: ${item.action}. Details: ${item.details}.`);
      });
    } else {
      parts.push("Action 1: Isolate the network interface to prevent lateral movement. Action 2: Terminate unauthorized memory handles. Action 3: Purge unverified persistence entries.");
    }

    parts.push("Stark defense grids are standing by. Awaiting your command, sir.");
    return parts.join(' ');
  }

  // 2. Generate File-only Script
  public generateFileScript(report: FullAnalysisReport | null): string {
    if (!report) {
      return "Sir, no sample payload has been loaded for inspection. Please submit a file to analyze.";
    }
    const parts: string[] = [];
    parts.push(`Sir, here is the dedicated forensic breakdown for sample ${report.sample_name}.`);
    parts.push(`This file scored ${report.threat_scoring.threat_score} out of 100, classified as a ${report.threat_scoring.severity} priority ${report.threat_scoring.verdict}.`);

    if (report.static_analysis?.pe_structure?.is_packed) {
      parts.push(`Static analysis indicates the binary is packed using high entropy evasion techniques.`);
    }

    if (report.threat_scoring.risk_factors && report.threat_scoring.risk_factors.length > 0) {
      parts.push(`High risk factors include: ${report.threat_scoring.risk_factors.join('. ')}.`);
    }

    if (report.mitre_mapping?.mapped_techniques && report.mitre_mapping.mapped_techniques.length > 0) {
      const topTech = report.mitre_mapping.mapped_techniques.slice(0, 3).map(t => `${t.technique_id} - ${t.technique_name}`).join(', ');
      parts.push(`Mapped adversarial techniques under MITRE ATT&CK include: ${topTech}.`);
    }

    parts.push("Recommendation: Do not execute this payload outside of an isolated hypervisor sandbox.");
    return parts.join(' ');
  }

  // 3. Generate Host-only Script
  public generateSystemScript(host: HostAssessment | null): string {
    if (!host) {
      return "Sir, live endpoint telemetry is currently unavailable. Initiating system scanner now.";
    }
    const parts: string[] = [];
    parts.push(`Sir, telemetry report for local host ${host.host_info.hostname}, running on ${host.host_info.os}.`);
    parts.push(`System health stands at ${host.health_score} out of 100, status: ${host.status}, with an alert level of ${host.alert_level}.`);

    const susp = host.active_threats.filter(t => t.is_suspicious);
    if (susp.length > 0) {
      parts.push(`I have flagged ${susp.length} active anomalies in host processes.`);
      susp.slice(0, 3).forEach(p => {
        parts.push(`Process ${p.name}, PID ${p.pid}: ${p.anomaly_reason}.`);
      });
    } else {
      parts.push("No rogue processes are currently consuming host CPU cycles.");
    }

    if (host.persistence_items && host.persistence_items.filter(pi => pi.is_suspicious).length > 0) {
      const count = host.persistence_items.filter(pi => pi.is_suspicious).length;
      parts.push(`Warning: detected ${count} unverified startup registry persistence mechanisms.`);
    }

    if (host.software_audit && host.software_audit.vulnerability_count > 0) {
      parts.push(`Total detected software CVE vulnerabilities: ${host.software_audit.vulnerability_count}.`);
    }

    return parts.join(' ');
  }

  // 4. Generate Solution & Remediation Script
  public generateSolutionScript(report: FullAnalysisReport | null, host: HostAssessment | null): string {
    const parts: string[] = [];
    parts.push("Sir, here are the step-by-step remediation procedures to secure this system and neutralize the threat.");

    if (host && host.remediation_plan && host.remediation_plan.length > 0) {
      host.remediation_plan.forEach((item, idx) => {
        parts.push(`Step ${idx + 1} with ${item.urgency} priority: ${item.action}. ${item.details}`);
      });
    } else {
      parts.push("Step 1: Sever external network adapters and block C2 IP connections on the local perimeter firewall.");
      parts.push("Step 2: Force-terminate suspicious worker processes identified during the memory scan.");
      parts.push("Step 3: Remove persistent registry keys under CurrentVersion Run and Scheduled Tasks.");
      parts.push("Step 4: Flush DNS resolver cache and quarantine the suspicious payload.");
    }

    if (report && report.ioc_extraction && report.ioc_extraction.total_extracted > 0) {
      parts.push(`Additionally, import all ${report.ioc_extraction.total_extracted} extracted IOC hashes and domain rules into your enterprise endpoint detection rules.`);
    }

    parts.push("Remediation plan ready for execution, sir.");
    return parts.join(' ');
  }

  // Speak method with word boundaries and event handlers
  public speak(
    text: string, 
    topic: 'full' | 'file' | 'system' | 'solution' = 'full',
    onWord?: (word: string, charIndex: number) => void,
    onFinished?: () => void
  ) {
    if (!this.synth) {
      alert("Text-to-speech is not supported by your browser.");
      return;
    }

    // Stop any existing speech
    this.stop();

    // Play Stark start chirp
    this.playStarkChirp();

    this.state = {
      isSpeaking: true,
      isPaused: false,
      currentText: text,
      activeTopic: topic,
      currentWord: '',
      currentCharIndex: 0
    };
    this.notify();

    const utterance = new SpeechSynthesisUtterance(text);
    this.currentUtterance = utterance;

    if (this.selectedVoice) {
      utterance.voice = this.selectedVoice;
    }
    utterance.rate = this.rate;
    utterance.pitch = this.pitch;

    utterance.onboundary = (event: SpeechSynthesisEvent) => {
      if (event.name === 'word') {
        const charIdx = event.charIndex;
        const remaining = text.substring(charIdx);
        const match = remaining.match(/\S+/);
        const word = match ? match[0].replace(/[.,;:!?]/g, '') : '';
        this.state.currentWord = word;
        this.state.currentCharIndex = charIdx;
        this.notify();
        if (onWord) onWord(word, charIdx);
      }
    };

    utterance.onend = () => {
      this.state.isSpeaking = false;
      this.state.isPaused = false;
      this.state.currentWord = '';
      this.notify();
      cyberAudio.playClick();
      if (onFinished) onFinished();
    };

    utterance.onerror = (e) => {
      console.warn("J.A.R.V.I.S. speech error:", e);
      this.state.isSpeaking = false;
      this.state.isPaused = false;
      this.notify();
    };

    this.synth.speak(utterance);
  }

  public pause() {
    if (this.synth && this.state.isSpeaking) {
      this.synth.pause();
      this.state.isPaused = true;
      this.notify();
    }
  }

  public resume() {
    if (this.synth && this.state.isPaused) {
      this.synth.resume();
      this.state.isPaused = false;
      this.notify();
    }
  }

  public stop() {
    if (this.synth) {
      this.synth.cancel();
    }
    this.state.isSpeaking = false;
    this.state.isPaused = false;
    this.state.currentWord = '';
    this.notify();
  }
}

export const jarvisVoice = new JarvisVoiceEngine();
