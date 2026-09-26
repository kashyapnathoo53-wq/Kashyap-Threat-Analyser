# PASHA 2.0 — INVESTIGATION ORCHESTRATION SPECIFICATION

**Document Version:** 2.0.0  
**Status:** Implemented & Verified (Milestone 5 Completed)  
**Target Platform:** Windows 10/11 (Local-First Architecture)  

---

## 1. Overview & Architecture

In Pasha 2.0, **Investigation Orchestration** (`agent/orchestration/investigator.py`) forms the critical bridge connecting host candidate discovery (Milestone 4) to Pasha's existing, proven malware analysis engines.

Rather than reinventing static analysis, YARA scanning, or sandbox emulation, the orchestrator automatically feeds suspicious candidates into Pasha's existing analytical pipeline:

```
┌────────────────────────────────┐
│        CANDIDATE QUEUE         │
│  (Prioritized Suspicious Items)│
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────┐
│   INVESTIGATION ORCHESTRATOR   │
│  • Target Acquisition (Binary  │
│    or Script Envelope)         │
│  • Status -> "ANALYZING"       │
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────┐
│               EXISTING MALWARE ANALYZERS               │
│  ┌───────────────────────┐   ┌───────────────────────┐ │
│  │ StaticAnalyzer        │   │ YaraEngine            │ │
│  │ (PE, Hashes, Entropy) │   │ (Signature Matches)   │ │
│  └───────────┬───────────┘   └───────────┬───────────┘ │
│              └─────────────┬─────────────┘             │
│                            ▼                           │
│              ┌───────────────────────────┐             │
│              │ BehavioralEmulator        │             │
│              │ (Syscalls, Registry, Net) │             │
│              └─────────────┬─────────────┘             │
│                            ▼                           │
│              ┌───────────────────────────┐             │
│              │ IocExtractor              │             │
│              │ (IPs, Domains, Hashes)    │             │
│              └─────────────┬─────────────┘             │
│                            ▼                           │
│              ┌───────────────────────────┐             │
│              │ MitreMapper               │             │
│              │ (ATT&CK Matrix Layer)     │             │
│              └─────────────┬─────────────┘             │
│                            ▼                           │
│              ┌───────────────────────────┐             │
│              │ ThreatScorer (0 - 100)    │             │
│              │ & Automated Verdict       │             │
│              └───────────────────────────┘             │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                  ANALYSIS REPORT & LINK                │
│  • Report persisted to disk (`agent/data/reports/`)   │
│  • Candidate status transitioned to "ANALYZED"         │
│  • Candidate `analysis_report_id` set to Report SHA256 │
└────────────────────────────────────────────────────────┘
```

---

## 2. Target Acquisition & Ingestion Modes

The orchestrator inspects the candidate's telemetry to extract the inspection payload:

1. **Physical Binary Files:**
   * When `candidate.target_path` points to a local file (e.g. process executable, service binary, or downloaded payload in `Downloads`/`Temp`), the orchestrator safely reads the file in read-only mode (`"rb"`).
   * **Guardrail:** Reads are capped at 50 MB (`MAX_FILE_READ_BYTES`) to protect host memory.
2. **In-Memory & Command-Line Threats:**
   * When a candidate is an active process or persistence item without an accessible physical binary (e.g. encoded PowerShell command, script execution, or process terminated prior to disk read), the orchestrator packages `candidate.cmdline` into a UTF-8 script envelope (`filename.script`).
   * The static and behavioral engines inspect the script's raw strings, decoded commands, and behavioral invocations.
3. **Synthetic Diagnostic Artifact:**
   * If neither binary nor command line is accessible, a diagnostic telemetry envelope is generated from matched heuristics and metadata.

---

## 3. Candidate Lifecycle Updates

During investigation, candidate state transitions occur atomically:

1. **`QUEUED` $\rightarrow$ `ANALYZING`:**
   * Candidate is locked for investigation to avoid duplicate processing in batch operations.
2. **Execution:**
   * `run_full_analysis(filename, content)` runs all 6 analytical stages.
3. **`ANALYZING` $\rightarrow$ `ANALYZED`:**
   * Candidate's `status` is updated to `ANALYZED`.
   * Candidate's `analysis_report_id` is updated to the report's SHA-256 identifier.
   * Report is persisted to `backend/agent/data/reports/report_{id}.json` and cached in `analysis_store`.

---

## 4. REST API Reference

### 4.1 `POST /api/agent/investigate/next`
Pulls and investigates the highest-priority pending candidate in the queue.

**Sample Response (HTTP 200):**
```json
{
  "status": "success",
  "candidate_id": "cand_svc_2ad38c89",
  "report_id": "b557ba2ff4def2a2a2a304da1ca9bf3eb345fd076934ba00b4acc67d1ac403d9",
  "sample_name": "CptService.exe",
  "threat_score": 33,
  "verdict": "LOW RISK",
  "candidate": {
    "candidate_id": "cand_svc_2ad38c89",
    "name": "ZoomCptServiceForVDIPluginMgmt",
    "status": "ANALYZED",
    "analysis_report_id": "b557ba2ff4def2a2a2a304da1ca9bf3eb345fd076934ba00b4acc67d1ac403d9",
    "priority_score": 80
  },
  "report": {
    "report_id": "b557ba2ff4def2a2a2a304da1ca9bf3eb345fd076934ba00b4acc67d1ac403d9",
    "static_analysis": { ... },
    "yara_scan": { ... },
    "behavioral_analysis": { ... },
    "ioc_extraction": { ... },
    "mitre_mapping": { ... },
    "threat_scoring": {
      "threat_score": 33,
      "verdict": "LOW RISK"
    }
  }
}
```

---

### 4.2 `POST /api/agent/investigate/{candidate_id}`
Triggers deep analysis on a specific candidate by ID.

---

### 4.3 `POST /api/agent/investigate/batch?count=3`
Sequentially investigates the next `count` prioritized candidates in the queue.

**Sample Response:**
```json
{
  "status": "success",
  "investigated_count": 2,
  "results": [ ... ]
}
```

---

### 4.4 `GET /api/agent/candidates/{candidate_id}/report`
Retrieves the full analysis report linked to an analyzed candidate.

* Returns `HTTP 200` with the complete `FullAnalysisReport` object.
* Returns `HTTP 404` if the candidate does not exist or has not been analyzed yet.
