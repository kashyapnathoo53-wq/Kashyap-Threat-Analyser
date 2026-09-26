import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable

from agent.models.candidate import SuspiciousCandidate, CandidateStatus
from agent.storage.candidate_queue import CandidateQueue

logger = logging.getLogger("pasha.agent.orchestrator")

MAX_FILE_READ_BYTES = 52428800  # 50 MB limit for safety


class InvestigationOrchestrator:
    """
    Connects queued host security candidates from Pasha 2.0 Local Agent
    directly to Pasha's existing malware analysis engines (Static, YARA,
    Behavioral, IOC, and MITRE scoring).
    """

    def __init__(
        self,
        candidate_queue: CandidateQueue,
        analysis_fn: Callable[[str, bytes], Dict[str, Any]],
        analysis_store: Optional[Dict[str, Any]] = None,
        reports_dir: Optional[str] = None
    ):
        self.queue = candidate_queue
        self.analyze = analysis_fn
        self.analysis_store = analysis_store if analysis_store is not None else {}
        
        if reports_dir:
            self.reports_dir = Path(reports_dir)
        else:
            current_dir = Path(__file__).resolve().parent.parent
            self.reports_dir = current_dir / "data" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)


    def prepare_candidate_payload(self, candidate: SuspiciousCandidate) -> Tuple[str, bytes]:
        """
        Safely acquires binary content for physical target files or synthesizes
        a script inspection payload for in-memory / command-line threats.
        """
        target_path = candidate.target_path
        if target_path:
            clean_path = target_path.strip("\"' ")
            p = Path(clean_path)
            if p.is_file() and p.exists():
                try:
                    file_size = p.stat().st_size
                    if file_size <= MAX_FILE_READ_BYTES:
                        with open(p, "rb") as f:
                            content = f.read()
                        filename = p.name or candidate.name
                        return (filename, content)
                except Exception as e:
                    logger.warning(f"Could not read local file {clean_path}: {e}")

        # Fallback to command line or script representation
        if candidate.cmdline:
            filename = f"{candidate.name}.script" if not candidate.name.endswith((".bat", ".ps1", ".cmd", ".vbs")) else candidate.name
            content = candidate.cmdline.encode("utf-8", errors="replace")
            return (filename, content)

        # Fallback: Synthesize descriptive investigation artifact
        filename = f"{candidate.name}.threat"
        info = (
            f"; Pasha Synthetic Threat Telemetry Envelope\n"
            f"name={candidate.name}\n"
            f"category={candidate.category}\n"
            f"heuristics={','.join(candidate.heuristics_matched)}\n"
            f"priority={candidate.priority_score}\n"
        )
        return (filename, info.encode("utf-8"))

    def investigate_candidate(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        """
        Executes an end-to-end investigation on a specific candidate:
        1. Transitions status to ANALYZING.
        2. Acquires binary/script content.
        3. Executes full analytical pipeline (Static, YARA, Behavioral, IOC, MITRE, Threat Scoring).
        4. Transitions status to ANALYZED and links generated report_id.
        """
        candidate = self.queue.get_candidate(candidate_id)
        if not candidate:
            return None

        # 1. State transition -> ANALYZING
        self.queue.update_status(candidate_id, "ANALYZING")

        # 2. Acquire payload
        filename, content = self.prepare_candidate_payload(candidate)

        # 3. Execute existing analysis pipeline
        report = self.analyze(filename, content)
        report_id = report.get("report_id")

        # 4. State transition -> ANALYZED with linked report ID
        updated = self.queue.update_status(candidate_id, "ANALYZED", report_id=report_id)

        # Cache in analysis_store and persist to disk
        if report_id:
            self.analysis_store[report_id] = report
            try:
                report_file = self.reports_dir / f"report_{report_id}.json"
                with open(report_file, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
            except Exception as e:
                logger.warning(f"Could not persist report {report_id} to disk: {e}")

        return {
            "status": "success",
            "candidate_id": candidate_id,
            "report_id": report_id,
            "sample_name": filename,
            "threat_score": report.get("threat_scoring", {}).get("threat_score", 0),
            "verdict": report.get("threat_scoring", {}).get("verdict", "UNKNOWN"),
            "candidate": updated.model_dump(mode="json") if updated else candidate.model_dump(mode="json"),
            "report": report
        }

    def investigate_next(self) -> Optional[Dict[str, Any]]:
        """
        Pulls the highest-priority pending candidate and executes deep analysis.
        """
        next_cand = self.queue.get_next_queued_candidate()
        if not next_cand:
            return None
        return self.investigate_candidate(next_cand.candidate_id)

    def investigate_batch(self, max_count: int = 3) -> List[Dict[str, Any]]:
        """
        Investigates up to max_count candidates sequentially.
        """
        results = []
        for _ in range(max(1, max_count)):
            res = self.investigate_next()
            if not res:
                break
            results.append(res)
        return results

    def get_candidate_report(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the cached or persisted analysis report for an analyzed candidate.
        """
        cand = self.queue.get_candidate(candidate_id)
        if not cand or not cand.analysis_report_id:
            return None

        report_id = cand.analysis_report_id
        if report_id in self.analysis_store:
            return self.analysis_store[report_id]

        # Load from disk storage if available
        report_file = self.reports_dir / f"report_{report_id}.json"
        if report_file.exists():
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.analysis_store[report_id] = data
                return data
            except Exception:
                pass

        return None

