# PASHA 2.0 — ARCHITECTURE AUDIT & TECHNICAL SPECIFICATION

**Document Version:** 2.0.0  
**Status:** Approved / Milestone 0 Completed  
**Repository:** `Kashyap-Threat-Analyser`  
**Target Platform:** Windows 10/11 (Local-First Architecture)  

---

## 1. Executive Summary & Vision

**Pasha** is an automated malware analysis and host threat assessment platform. Historically, Pasha operated primarily as a file-upload sandbox: users provided a suspect binary or script, and Pasha executed static inspection, YARA signature evaluation, behavioral simulation, IOC extraction, MITRE ATT&CK mapping, and threat risk scoring.

**Pasha 2.0 Evolution:**
The platform is transitioning into a **Windows-first local security investigation platform**. Rather than requiring a user or analyst to already know which file is malicious, Pasha automatically inspects the local Windows machine, creates security snapshots, computes security diffs ("What changed?"), detects suspicious candidates automatically, and investigates those candidates using Pasha's existing analytical engines.

### Core Architectural Principle
```
Browser Extension          = Thin UI & Browser Context
Pasha Local Agent          = Read-Only Windows Host Collectors & Snapshot Engine
Pasha Investigation Engine = Reused Static, YARA, Behavioral, IOC, & MITRE Analyzers
Pasha Web App              = Clean, Preserved Dashboard, Timeline, & Evidence Visualizer
```

---

## 2. Current Architecture (Pasha 1.x / Current Monorepo)

### 2.1 Technology Stack

| Layer | Technologies | Current Responsibility |
|---|---|---|
| **Frontend** | React 18, Vite 5, TypeScript 5, Tailwind CSS 3, Recharts, Lucide Icons | Dashboard visualization, interactive tabs, SVG Arc Reactor, audio synthesizers, offline fallback |
| **Backend** | Python 3, FastAPI, Uvicorn, Pydantic v2 | Analytical core REST API, host process/registry/software auditing, report compilation |
| **Data Storage** | In-Memory Dictionaries (`analysis_store`, `latest_host_assessment`), Browser `localStorage` | Ephemeral runtime report caching and theme/audio preferences |
| **Integration** | Web Speech API, Web Audio API, Gemini 1.5 Flash (Optional REST) | Voiced status teleprompter, synthesized audio cues, AI remediation advice |

### 2.2 Current Monorepo Layout
```
Kashyap-Threat-Analyser/
├── backend/                       # Python FastAPI backend
│   ├── main.py                    # REST API entrypoint & orchestration
│   ├── static_analyzer.py         # Binary/PE/Script static inspection
│   ├── behavioral_emulator.py     # Sandbox process & syscall simulation
│   ├── yara_engine.py             # YARA rule compilation & scanning
│   ├── ioc_extractor.py           # Regex-based IOC parser
│   ├── mitre_mapper.py            # ATT&CK v14+ matrix correlation
│   ├── threat_scorer.py           # Multi-factor threat risk score (0-100)
│   ├── host_scanner.py            # Local process, RunKey & CVE scanner
│   ├── ai_assistant.py            # Gemini & heuristic chat/remediation
│   ├── reporter.py                # STIX 2.1, MISP, HTML, Markdown generator
│   ├── samples_generator.py       # Preset samples (WannaCry, Emotet, etc.)
│   ├── run_tests.py               # Analytical pipeline test suite
│   └── requirements.txt           # fastapi, uvicorn, pydantic, python-multipart
│
├── frontend/                      # React SPA
│   ├── src/
│   │   ├── App.tsx                # Master state coordinator & layout
│   │   ├── types.ts               # Core domain interfaces
│   │   ├── index.css              # Cyber glassmorphic theme system
│   │   ├── components/            # UI Tabs, modals, HUD widgets
│   │   ├── data/mockReports.ts    # Fallback reports for offline/Vercel
│   │   └── utils/                 # Audio, voice, client-side fallback
│   ├── package.json
│   ├── vite.config.ts             # Port 3000 -> proxy to backend:8000
│   └── tailwind.config.js
│
├── package.json                   # Root monorepo script coordinator
├── vercel.json                    # Vercel deployment rewrite rules
└── README.md
```

---

## 3. Current Data Flow & Pipeline Analysis

```
[ User Action: Upload File OR Select Preset OR Run Host Assessment ]
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
    POST /api/analyze/upload        GET /api/system/auto-assess
    (or /api/analyze/preset)                   │
               │                               ▼
               ▼                      host_scanner.py
     run_full_analysis()              - tasklist CSV parsing
               │                      - WinReg RunKey queries
    ┌──────────┴──────────┐           - Software version vs CVE catalog
    ▼                     ▼           - Threat forecast generation
StaticAnalyzer       YaraEngine                │
(hashes, PE, ent)    (signatures)              ▼
    │                     │           latest_host_assessment
    └──────────┬──────────┘                    │
               ▼                               ▼
      BehavioralEmulator              [ React App: SystemAssessmentTab ]
      (emulated syscalls,              - Radial health score (0-100)
       process hierarchy)              - Flagged processes
               │                       - CVE software list
               ▼                       - Actionable remediation plan
          IocExtractor
          (IPs, URLs, wallets)
               │
               ▼
          MitreMapper
          (ATT&CK TTPs & Navigator)
               │
               ▼
         ThreatScorer
         (0-100 weighted risk score)
               │
               ▼
          Reporter
          (STIX, MISP, HTML, MD)
               │
               ▼
      [ React App: Overview & Forensic Tabs ]
```

---

## 4. Detailed Component & Module Reusability Matrix

The existing Pasha modules were analyzed for direct reuse in Pasha 2.0:

| Module | Current File | Quality & Status | Reuse in Pasha 2.0 |
|---|---|---|---|
| **Static Analyzer** | `backend/static_analyzer.py` | High. Fast streaming hashes (MD5, SHA1, SHA256, SHA512, SSDEEP), chunked entropy, PE section analysis, and auto-string decoders (Base64, XOR). | **100% Reused** for inspecting files identified by the Local Agent. |
| **YARA Engine** | `backend/yara_engine.py` | High. Clean condition evaluator, pre-loaded ransomware, infostealer, webshell, keylogger, and injection rules; supports custom rule registration. | **100% Reused** to evaluate suspicious candidate binaries and memory dumps. |
| **Behavioral Emulator** | `backend/behavioral_emulator.py` | Medium. Heuristic sandbox simulator producing realistic Syscalls, process trees, and registry changes. | **Reused & Enhanced**. In Pasha 2.0, this provides behavioral simulation for dormant files, while the Local Agent captures *real observed* runtime telemetry. |
| **IOC Extractor** | `backend/ioc_extractor.py` | High. Robust bounded regex patterns for IPv4, URLs, FQDNs, hashes, registry keys, and crypto addresses (BTC, ETH). | **100% Reused** for extracting network, file, and host indicators. |
| **MITRE Mapper** | `backend/mitre_mapper.py` | High. Correlates indicators across 12 ATT&CK tactics; exports v14 Navigator JSON layer. | **100% Reused** to align discovered adversary behaviors with enterprise tactics. |
| **Threat Scorer** | `backend/threat_scorer.py` | Good. Normalized weighted score (0–100) across static, YARA, behavioral, IOC, and MITRE components. | **Reused as Foundation**, extended in Milestone 9 into distinct **Risk (0-100)** and **Confidence (%)** metrics. |
| **Host Scanner** | `backend/host_scanner.py` | Good functional MVP, but procedural and monolithic. | **Architecture Source**: Reorganized in Milestone 1 into modular read-only collectors (`agent/collectors/`). |
| **AI Assistant** | `backend/ai_assistant.py` | Good. Produces 6-phase remediation roadmaps and answers user triage questions. | **Reused** to generate contextual attack story summaries and user-confirmed cleanup steps. |
| **Reporter** | `backend/reporter.py` | High. Exports STIX 2.1 JSON, MISP JSON, HTML executive dossiers, and Markdown. | **Reused & Extended** for Milestone 11 Evidence Preservation ZIP packages. |

---

## 5. Existing APIs & Endpoints

| Method | Endpoint | Description | Request / Response Payload |
|---|---|---|---|
| `GET` | `/` | Service root ping | `{"status": "online", "platform": "Pasha v2.0"}` |
| `GET` | `/api/health` | Engine health check | Returns list of registered analytical engines |
| `GET` | `/api/system/auto-assess` | Full host security evaluation | Returns host info, health score, processes, CVEs, remediation |
| `GET` | `/api/system/quick-status` | Lightweight host health pill | Returns health score, status string, color, alert level |
| `GET` | `/api/samples/presets` | List pre-loaded malware samples | Returns IDs, names, and descriptions of preset binaries |
| `POST` | `/api/analyze/upload` | Upload & analyze physical file | Multipart file -> FullAnalysisReport |
| `POST` | `/api/analyze/preset` | Analyze preset sample by ID | `{"sample_id": "sample_wannacry"}` -> FullAnalysisReport |
| `GET` | `/api/reports/{id}` | Retrieve report by SHA256 ID | Returns cached FullAnalysisReport |
| `GET` | `/api/yara/rules` | List compiled YARA rules | Returns active rule catalog |
| `POST` | `/api/yara/rules` | Add custom YARA rule | `CustomYaraRequest` -> Compiled rule confirmation |
| `POST` | `/api/ai/eradication-roadmap` | Generate remediation plan | `{report, host_assessment}` -> 6-phase roadmap nodes |
| `POST` | `/api/jarvis/chat` | Triage chat assistant | `{message, report, host_assessment, history}` -> `reply` |
| `GET` | `/api/reports/{id}/export/{format}` | Export report (stix/misp/md/html) | Returns respective structured payload or document |

---

## 6. Existing UI Structure & Visual Language

### 6.1 Visual Identity
* **Theme System:** Cyber dark aesthetic with dynamic CSS custom properties (`--cyber-bg`, `--cyber-panel-bg`, `--cyber-accent`, `--cyber-border`, `--cyber-laser`).
* **Presets:** 7 themes (Arc Cyan default, Tactical Cobalt, Matrix Emerald, Neon Violet, Stealth Crimson, Stealth Carbon, Stark Armor) + Custom Hex Color Picker.
* **Key Components:**
  * **HoloReactorCore:** Animated SVG Arc Reactor visualizing threat severity and score.
  * **CyberParticleCanvas:** Lightweight 60fps canvas filament particle background.
  * **LiveTelemetryTerminal:** Docked bottom HUD displaying real-time simulated security events.
  * **SectionGuide:** Standardized collapsible guidance card on each tab explaining purpose, analyst value, and key signals.
  * **Navigation Rail:** Segmented pill bar switching between analytical views with sound effects.

### 6.2 Existing UI Tabs
1. **System Auto-Assessment (`host`):** Radial health score, monitored processes, software CVE audit, predictive forecast, and remediation plan.
2. **Executive Overview (`overview`):** High-level verdict, confidence, multi-factor score breakdown bar chart, and critical alert badges.
3. **Static Analysis (`static`):** Cryptographic hashes (MD5, SHA1, SHA256, SSDEEP), entropy area chart, imported Win32 APIs, decoded Base64/XOR strings.
4. **Behavioral Sandbox (`sandbox`):** Interactive process hierarchy tree, filterable Win32 Syscall trace log, dropped filesystem items, registry RunKeys, network beacons.
5. **MITRE ATT&CK (`mitre`):** 12-tactic adversary board, technique evidence cards, ATT&CK Navigator JSON download.
6. **Extracted IOCs (`iocs`):** Category-filtered indicator table with confidence ratings, STIX 2.1, MISP, and CSV downloads.
7. **YARA Workbench (`yara`):** Signature match cards with offset details and interactive YARA rule editor.
8. **Automated Report (`report`):** Live responsive HTML report viewer, Markdown exporter, and print-to-PDF button.

---

## 7. Audit Findings: Current Deficiencies & Inconsistencies

1. **Host Processes Tab Mismatch:**
   - In `SystemAssessmentTab.tsx`, the tab header displays `Host Processes (${summary.total_processes_scanned})` (e.g. 316), but the table only iterates over `safeThreats` (anomalous processes). If no suspicious processes are detected, an empty table is rendered despite the header count.
2. **Data Model / Contract Discrepancies:**
   - `HostAssessment.active_threats.pid` is typed as `number` in TypeScript, but backend `host_scanner.py` returns a string.
   - `HostAssessment.active_threats.threat_level` is marked required in `types.ts`, but omitted by `host_scanner.py`.
   - `HostAssessment.host_info.python_version` is required in `types.ts`, but returned inside `installed_software` rather than `host_info`.
3. **Ephemeral In-Memory Storage:**
   - Reports and host assessments are stored in Python memory dictionaries (`analysis_store`, `latest_host_assessment`). Restarting the server clears all prior history. No snapshot persistence exists on disk.
4. **Reactive Rather Than Proactive Workflow:**
   - The user must either upload a sample manually or review high-level host statistics. The platform lacks an autonomous pipeline that scans targeted host directories (Downloads, Temp, AppData), identifies suspicious candidates, and dispatches them to the analyzer.
5. **Residual Color Hardcoding:**
   - Small sections of `App.tsx` (top bar, empty state text) and `ReportGeneratorTab.tsx` retain hardcoded amber/orange styles from prior themes rather than respecting the active theme tokens.

---

## 8. Proposed Pasha 2.0 Target Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │            PASHA WEB DASHBOARD               │
                    │   Preserved UI Visual Identity + Clean Flow  │
                    │   - "Scan My Computer" One-Click Entry       │
                    │   - Security Snapshot Diff Viewer            │
                    │   - Suspicious Candidate Discovery Feed      │
                    │   - Evidence Correlation & Attack Story      │
                    │   - Risk (0-100) vs Confidence (%) Gauges    │
                    │   - Security Timeline & Blast Radius Impact  │
                    │   - User-Confirmed Remediation Panel         │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           │ REST API / WebSockets
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │               PASHA CORE API                 │
                    │   (FastAPI Backend / Orchestration Engine)   │
                    └───────┬──────────────────────────────┬───────┘
                            │                              │
                            ▼                              ▼
      ┌─────────────────────────────────┐   ┌──────────────────────────────────┐
      │        LOCAL AGENT ENGINE       │   │   EXISTING MALWARE ANALYZERS     │
      │   (Read-Only Windows Inspection)│   │   (Reused Analytical Engines)    │
      ├─────────────────────────────────┤   ├──────────────────────────────────┤
      │ • Process Collector (PID, CLI)  │   │ • StaticAnalyzer (PE, Entropy)   │
      │ • File Collector (Temp, AppData)│──►│ • YaraEngine (Preloaded+Custom)  │
      │ • Persistence (RunKey, Tasks)   │   │ • BehavioralEmulator (Sandbox)   │
      │ • Service Collector             │   │ • IocExtractor (STIX, MISP, CSV) │
      │ • Network Sockets (Active TCP)  │   │ • MitreMapper (ATT&CK v14 Layer) │
      │ • Security Snapshot Store (JSON)│   │ • ThreatScorer & Confidence      │
      │ • Security Diff Engine          │   └──────────────────────────────────┘
      │ • Candidate Detector & Queue    │
      └─────────────────────────────────┘
```

### Key Architectural Tenets for Pasha 2.0:
1. **Zero Uncontrolled Scanning:** Scans target security-critical attack surfaces (Downloads, Temp, AppData, Startup, RunKeys, active TCP listeners) rather than whole-drive traversal.
2. **Strict Read-Only Local Agent MVP:** The agent collects and evaluates evidence. It never modifies, terminates, or deletes anything without explicit, modal-confirmed user consent.
3. **Explainable Candidate Scoring:** Candidates are prioritized by clear heuristics (e.g. executing from Temp + unsigned + network socket) before being sent to the malware analysis pipeline.
4. **Evidence Correlation & Graph:** Every conclusion links back to observed facts (Process -> Binary -> Hash -> YARA hit -> C2 socket -> MITRE technique).
5. **Preserved UI Language:** The new investigation features embed directly into the existing Pasha dashboard using the current glassmorphic card language, theme studio, and interactive components.

---

## 9. Milestone Implementation Roadmap

* **Milestone 0: Existing Project Audit** *(Completed)*
  * Thorough inspection of backend engines, frontend components, and APIs.
  * Verification of test suite execution (`run_tests.py` passing).
  * Creation of comprehensive architecture specification (`docs/PASHA_ARCHITECTURE.md`).
* **Milestone 1: Windows Local Agent (Read-Only Collectors)**
  * Implement modular collectors in `agent/collectors/` (Processes, Files, Persistence, Services, Scheduled Tasks, Network).
  * Safe error-handling per collector (partial scans allowed if permissions restricted).
* **Milestone 2: Security Snapshot Normalization & Storage**
  * Define versioned JSON snapshot schema.
  * Implement local disk storage for snapshots with retention management.
* **Milestone 3: Security Diff Engine**
  * Compare consecutive snapshots to identify new/modified/removed processes, files, persistence, and sockets.
* **Milestone 4: Automatic Suspicious Candidate Detection**
  * Implement candidate prioritization heuristics and explainable score.
  * Candidate queue model (`DISCOVERED`, `QUEUED`, `ANALYZING`, `ANALYZED`).
* **Milestone 5: Investigation Orchestration**
  * Connect candidates automatically to Pasha's Static, YARA, Behavioral, IOC, and MITRE engines.
* **Milestone 6: Evidence Correlation & Attack Story**
  * Link multiple indicators into an interconnected evidence chain.
* **Milestone 7: Security Timeline**
  * Chronological reconstruction of observed host and file events.
* **Milestone 8: Impact & Blast Radius Analysis**
  * Visual mapping of affected processes, files, registry keys, and network connections.
* **Milestone 9: Risk vs. Confidence Metric Separation**
  * Mathematical separation of Risk Severity (0–100) and Evidentiary Confidence (0–100%).
* **Milestone 10: User-Confirmed Response & Remediation**
  * Explicit modal confirmations for process termination, quarantine, and RunKey cleanup.
* **Milestone 11: Evidence Preservation Packages**
  * Structured export of incident packages (ZIP/JSON) for forensics and chain of custody.
* **Milestone 12: Browser Extension (Thin UI)**
  * Chrome/Edge Manifest V3 extension for quick scan trigger and status view via Native Messaging.
* **Milestone 13: Dashboard Integration & UI Polish**
  * Integrate "Scan My Computer", Security Diff, and Candidate Investigation into the clean Pasha UI.
