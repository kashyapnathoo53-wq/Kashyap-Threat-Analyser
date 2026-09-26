export interface HashInfo {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  ssdeep: string;
  size_bytes: number;
}

export interface FileInfo {
  type: string;
  architecture: string;
  magic_bytes: string;
  entropy: number;
}

export interface SectionInfo {
  name: string;
  virtual_size: string;
  raw_size: number;
  entropy: number;
  characteristics: string;
  is_suspicious: boolean;
}

export interface ImportInfo {
  dll: string;
  function: string;
  description: string;
  risk: string;
}

export interface DecodedString {
  original: string;
  type: string;
  decoded: string;
}

export interface StaticAnalysis {
  hashes: HashInfo;
  file_info: FileInfo;
  pe_structure: {
    sections: SectionInfo[];
    imports: ImportInfo[];
    import_count: number;
    is_packed: boolean;
    packer?: string;
    digital_signature: {
      signed: boolean;
      status: string;
      publisher: string;
    };
  };
  suspicious_imports?: ImportInfo[];
  strings: {
    ascii: string[];
    ascii_total: number;
    unicode: string[];
    unicode_total: number;
    decoded: DecodedString[];
  };
}

export interface YaraMatch {
  rule_id: string;
  rule_name: string;
  category: string;
  severity: string;
  description: string;
  matched_strings: string[];
  strings_matched?: string[];
  threat_level: number;
  meta?: { author?: string; [key: string]: any };
}

export interface YaraScan {
  matches: YaraMatch[];
  match_count: number;
  total_matches?: number;
  scan_duration_ms?: number;
  total_rules_scanned: number;
}

export interface ProcessNode {
  pid: number;
  name: string;
  path: string;
  cmd: string;
  integrity: string;
  children?: ProcessNode[];
}

export interface ApiCall {
  timestamp: number;
  pid: number;
  process: string;
  api: string;
  category: string;
  arguments: string;
  return_val: string;
  risk: string;
}

export interface BehavioralAnalysis {
  process_tree: ProcessNode;
  api_call_stream: ApiCall[];
  filesystem_activity: { action: string; path: string; size?: string; size_bytes?: number }[];
  registry_activity: { action: string; key: string; value?: string; value_name?: string; data?: string }[];
  network_activity: { proto?: string; protocol?: string; destination: string; domain?: string; type?: string; bytes_sent?: number }[];
  total_api_calls: number;
  execution_time_seconds: number;
}

export interface IocItem {
  type: string;
  value: string;
  category: string;
  confidence: number;
  threat_intel: Record<string, any>;
}

export interface IocExtraction {
  iocs: IocItem[];
  total_extracted: number;
  summary_by_category: Record<string, number>;
}

export interface MitreTechnique {
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  name?: string;
  description?: string;
  url?: string;
  evidence: string;
  confidence: string;
}

export interface MitreMapping {
  tactics: { id: string; name: string }[];
  mapped_techniques: MitreTechnique[];
  total_mapped_techniques: number;
  total_techniques_mapped?: number;
  detected_tactics?: any[];
  navigator_layer: any;
}

export interface ThreatScoring {
  threat_score: number;
  verdict: string;
  severity: string;
  color: string;
  confidence?: number;
  high_priority_flags?: string[];
  score_breakdown: {
    static_score: number;
    yara_score: number;
    behavioral_score: number;
    ioc_score: number;
    mitre_score: number;
  };
  risk_factors: string[];
}

export interface FullAnalysisReport {
  report_id: string;
  sample_name: string;
  timestamp: string;
  static_analysis: StaticAnalysis;
  yara_scan: YaraScan;
  behavioral_analysis: BehavioralAnalysis;
  ioc_extraction: IocExtraction;
  mitre_mapping: MitreMapping;
  threat_scoring: ThreatScoring;
}

export interface SoftwareVulnerability {
  software: string;
  installed_version: string;
  cve: string;
  severity: string;
  cvss: number;
  description: string;
  remediation: string;
}

export interface InstalledSoftwareItem {
  name: string;
  version: string;
  publisher: string;
  has_cve?: boolean;
  cve_id?: string;
  severity?: string;
}

export interface ThreatForecastItem {
  vector: string;
  probability: string;
  impact: string;
  reasoning: string;
  mitigation: string;
}

export interface RemediationItem {
  action: string;
  urgency: string;
  details: string;
}

export interface HostAssessment {
  timestamp: string;
  host_info: {
    hostname: string;
    os: string;
    architecture: string;
    python_version: string;
  };
  health_score: number;
  status: string;
  status_color: string;
  alert_level: string;
  summary: {
    total_processes_scanned: number;
    suspicious_processes: number;
    startup_items_scanned: number;
    suspicious_startup_items: number;
    installed_software_scanned: number;
    known_vulnerabilities_detected: number;
  };
  active_threats: {
    pid: number;
    name: string;
    path: string;
    is_suspicious: boolean;
    threat_level: string;
    anomaly_reason: string;
  }[];
  persistence_items: {
    name: string;
    command: string;
    location: string;
    is_suspicious: boolean;
    risk: string;
  }[];
  software_audit: {
    installed_software: InstalledSoftwareItem[];
    total_software_found: number;
    vulnerabilities: SoftwareVulnerability[];
    vulnerability_count: number;
  };
  threat_forecast: ThreatForecastItem[];
  remediation_plan: RemediationItem[];
}

// ==========================================
// PASHA 2.0 AUTONOMIC DEFENSE & AGENT TYPES
// ==========================================

export interface AgentStatus {
  status: string;
  agent_version: string;
  machine_id: string;
  storage: {
    total_snapshots: number;
    active_snapshots_retained: number;
    storage_directory: string;
    total_disk_bytes: number;
    total_disk_human: string;
  };
}

export interface SuspiciousCandidate {
  candidate_id: string;
  category: string;
  target_entity: string;
  process_name?: string;
  pid?: number;
  file_path?: string;
  snapshot_id?: string;
  priority_score: number;
  status: 'DISCOVERED' | 'QUEUED' | 'ANALYZING' | 'ANALYZED' | 'REMEDIATED' | 'IGNORED';
  heuristics_matched: string[];
  risk_score: number;
  confidence_score: number;
  discovered_at: string;
  investigated_at?: string;
}

export interface CandidateQueueSummary {
  total_candidates: number;
  counts_by_status: Record<string, number>;
  counts_by_category: Record<string, number>;
  average_priority_score: number;
  top_candidates: SuspiciousCandidate[];
}

export interface SecuritySnapshotSummary {
  snapshot_id: string;
  timestamp: string;
  host_info?: {
    hostname: string;
    os: string;
    architecture: string;
  };
  metrics?: {
    process_count: number;
    network_connection_count: number;
    persistence_count: number;
    scanned_file_count: number;
  };
}

export interface AttackStoryNode {
  id: string;
  type: string;
  label: string;
  severity: string;
  details?: Record<string, any>;
}

export interface AttackStoryEdge {
  source: string;
  target: string;
  relation: string;
}

export interface AttackStory {
  candidate_id: string;
  title: string;
  executive_summary: string;
  attack_narrative: string[];
  nodes: AttackStoryNode[];
  edges: AttackStoryEdge[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  root_cause: string;
  risk_assessment: {
    risk_score: number;
    confidence_score: number;
    verdict: string;
  };
}

export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  category: 'PROCESS' | 'PERSISTENCE' | 'NETWORK' | 'FILE' | 'ANALYSIS' | 'HEURISTIC';
  action: string;
  source: string;
  target: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface SecurityTimeline {
  candidate_id?: string;
  snapshot_id?: string;
  total_events: number;
  events: TimelineEvent[];
}

export interface BlastRadiusReport {
  target_entity: string;
  category: string;
  scope_level: 'ISOLATED_PROCESS' | 'LOCAL_USER' | 'PERSISTENCE_ONLY' | 'SYSTEM_WIDE';
  impact_score: number;
  severity: string;
  affected_processes: string[];
  affected_registry_keys: string[];
  affected_network_endpoints: string[];
  affected_files: string[];
  containment_recommendations: string[];
}

export interface DualMetrics {
  target_id: string;
  risk_score: number;
  risk_severity: string;
  confidence_score: number;
  confidence_level: string;
  evidence_signals_count: number;
  risk_breakdown: Record<string, number>;
  confidence_factors: Record<string, number>;
}

export interface RemediationDryRun {
  action: string;
  target_entity: string;
  is_safe: boolean;
  block_reason?: string;
  impact_description: string;
  confirmation_token: string;
  requires_user_confirmation: boolean;
}

export interface RemediationHistoryItem {
  execution_id: string;
  timestamp: string;
  action: string;
  target_entity: string;
  status: string;
  details: string;
}

export interface EvidencePackageSummary {
  package_id: string;
  created_at: string;
  candidate_id: string;
  target_entity: string;
  package_size_bytes: number;
  package_size_human: string;
  manifest_sha256: string;
  zip_sha256: string;
  file_count: number;
}

