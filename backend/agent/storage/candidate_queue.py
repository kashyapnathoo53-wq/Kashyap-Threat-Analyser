import os
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

from agent.models.candidate import SuspiciousCandidate, CandidateStatus, CandidateQueueSummary


class CandidateQueue:
    def __init__(self, storage_file: Optional[str] = None):
        if storage_file:
            self.file_path = Path(storage_file)
        else:
            current_dir = Path(__file__).resolve().parent.parent
            self.file_path = current_dir / "data" / "candidate_queue.json"

        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._candidates: Dict[str, SuspiciousCandidate] = {}
        self._load()

    def _load(self):
        """Loads candidates from disk storage if present."""
        if not self.file_path.exists():
            return
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    try:
                        cand = SuspiciousCandidate(**item)
                        self._candidates[cand.candidate_id] = cand
                    except Exception:
                        continue
        except Exception:
            pass

    def _save(self):
        """Persists candidates to disk atomically."""
        try:
            data = [c.model_dump(mode="json") for c in self._candidates.values()]
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _get_dedup_fingerprint(self, c: SuspiciousCandidate) -> str:
        cat = c.category.lower()
        target = (c.target_path or "").lower()
        sha = (c.sha256 or "").lower()
        name = c.name.lower()
        cmd = (c.cmdline or "").lower()
        if sha:
            return f"sha256:{sha}"
        if target:
            return f"target:{cat}:{target}"
        if cmd:
            return f"cmd:{cat}:{cmd}"
        return f"name:{cat}:{name}"

    def add_candidates(self, candidates: List[SuspiciousCandidate]) -> List[SuspiciousCandidate]:
        """
        Adds newly discovered candidates into queue, intelligently deduplicating
        against existing entries and updating priority if a higher score is observed.
        """
        existing_by_fp: Dict[str, SuspiciousCandidate] = {}
        for c in self._candidates.values():
            existing_by_fp[self._get_dedup_fingerprint(c)] = c

        added_or_updated: List[SuspiciousCandidate] = []

        for new_c in candidates:
            fp = self._get_dedup_fingerprint(new_c)
            if fp in existing_by_fp:
                existing = existing_by_fp[fp]
                # Merge heuristics and update score if higher
                merged_heuristics = list(set(existing.heuristics_matched + new_c.heuristics_matched))
                existing.heuristics_matched = merged_heuristics
                if new_c.priority_score > existing.priority_score:
                    existing.priority_score = new_c.priority_score
                if new_c.sha256 and not existing.sha256:
                    existing.sha256 = new_c.sha256
                if new_c.size_bytes and not existing.size_bytes:
                    existing.size_bytes = new_c.size_bytes
                self._candidates[existing.candidate_id] = existing
                added_or_updated.append(existing)
            else:
                self._candidates[new_c.candidate_id] = new_c
                existing_by_fp[fp] = new_c
                added_or_updated.append(new_c)

        self._save()
        return added_or_updated

    def get_candidate(self, candidate_id: str) -> Optional[SuspiciousCandidate]:
        return self._candidates.get(candidate_id)

    def list_candidates(
        self,
        status: Optional[str] = None,
        category: Optional[str] = None,
        limit: Optional[int] = 50,
        offset: int = 0
    ) -> List[SuspiciousCandidate]:
        """
        Lists candidates sorted by priority_score descending, with optional filtering.
        """
        items = list(self._candidates.values())

        if status:
            s_upper = status.upper()
            items = [i for i in items if i.status.value == s_upper or i.status == s_upper]

        if category:
            c_lower = category.lower()
            items = [i for i in items if i.category.lower() == c_lower]

        # Sort descending by priority score
        items.sort(key=lambda c: c.priority_score, reverse=True)

        paginated = items[offset:]
        if limit is not None and limit > 0:
            paginated = paginated[:limit]
        return paginated

    def update_status(
        self,
        candidate_id: str,
        new_status: str,
        report_id: Optional[str] = None
    ) -> Optional[SuspiciousCandidate]:
        cand = self._candidates.get(candidate_id)
        if not cand:
            return None

        status_clean = new_status.upper()
        cand.status = CandidateStatus(status_clean)
        if report_id:
            cand.analysis_report_id = report_id

        self._save()
        return cand

    def delete_candidate(self, candidate_id: str) -> bool:
        if candidate_id in self._candidates:
            del self._candidates[candidate_id]
            self._save()
            return True
        return False

    def get_next_queued_candidate(self) -> Optional[SuspiciousCandidate]:
        """
        Finds the highest priority candidate ready for investigation (QUEUED or DISCOVERED).
        """
        ready = [
            c for c in self._candidates.values()
            if c.status in [CandidateStatus.QUEUED, CandidateStatus.DISCOVERED]
        ]
        if not ready:
            return None
        ready.sort(key=lambda c: c.priority_score, reverse=True)
        return ready[0]

    def clear_queue(self):
        self._candidates.clear()
        self._save()

    def get_summary(self) -> CandidateQueueSummary:
        items = list(self._candidates.values())
        by_status: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        highest_score = 0

        for i in items:
            s_val = i.status.value if isinstance(i.status, CandidateStatus) else str(i.status)
            by_status[s_val] = by_status.get(s_val, 0) + 1
            by_category[i.category] = by_category.get(i.category, 0) + 1
            if i.priority_score > highest_score:
                highest_score = i.priority_score

        top = sorted(items, key=lambda c: c.priority_score, reverse=True)[:5]

        return CandidateQueueSummary(
            total_candidates=len(items),
            by_status=by_status,
            by_category=by_category,
            highest_priority_score=highest_score,
            top_candidates=top
        )
