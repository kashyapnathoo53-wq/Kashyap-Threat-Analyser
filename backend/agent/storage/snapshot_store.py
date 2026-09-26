import os
import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from agent.models.snapshot import SecuritySnapshot

class SnapshotStore:
    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir:
            self.base_dir = Path(storage_dir)
        else:
            # Default to backend/agent/data/snapshots
            current_dir = Path(__file__).resolve().parent.parent
            self.base_dir = current_dir / "data" / "snapshots"

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_snapshot_path(self, snapshot_id: str) -> Optional[Path]:
        """Resolves snapshot file path handling various ID or filename inputs."""
        clean_id = snapshot_id.strip()
        if clean_id.endswith(".json"):
            clean_id = clean_id[:-5]
        if clean_id.startswith("snapshot_"):
            raw_id = clean_id[9:]
        else:
            raw_id = clean_id

        candidates = [
            self.base_dir / f"snapshot_{clean_id}.json",
            self.base_dir / f"snapshot_{raw_id}.json",
            self.base_dir / f"{clean_id}.json",
            self.base_dir / f"{raw_id}.json",
        ]
        for path in candidates:
            if path.exists():
                return path
        return None

    def save_snapshot(self, snapshot: SecuritySnapshot, auto_prune: bool = True, max_snapshots: int = 50) -> str:
        """Saves a SecuritySnapshot as a versioned JSON document."""
        filename = f"snapshot_{snapshot.snapshot_id}.json"
        target_path = self.base_dir / filename

        # Dump model with by_alias=False to ensure normalized canonical keys
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(snapshot.model_dump_json(indent=2, by_alias=False))

        if auto_prune and max_snapshots > 0:
            try:
                self.prune_snapshots(max_snapshots=max_snapshots, max_age_days=None)
            except Exception:
                pass

        return str(target_path)

    def load_snapshot(self, snapshot_id: str) -> Optional[SecuritySnapshot]:
        """Loads and deserializes a SecuritySnapshot from disk."""
        target_path = self._resolve_snapshot_path(snapshot_id)
        if not target_path or not target_path.exists():
            return None

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return SecuritySnapshot(**data)
        except Exception:
            return None

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Safely removes a snapshot file from disk."""
        target_path = self._resolve_snapshot_path(snapshot_id)
        if target_path and target_path.exists():
            try:
                target_path.unlink()
                return True
            except OSError:
                return False
        return False

    def list_snapshots(self, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Lists all snapshots sorted newest first, returning lightweight metadata headers.
        """
        all_files = sorted(self.base_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
        paginated_files = all_files[offset:]
        if limit is not None and limit > 0:
            paginated_files = paginated_files[:limit]

        results = []
        for file in paginated_files:
            try:
                stat = file.stat()
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                results.append({
                    "snapshot_id": data.get("snapshot_id"),
                    "schema_version": data.get("schema_version", "2.0.0"),
                    "timestamp": data.get("timestamp"),
                    "host_id": data.get("host_id") or data.get("system_info", {}).get("machine_id", ""),
                    "hostname": data.get("system_info", {}).get("hostname", "Unknown"),
                    "os_version": data.get("os_version") or data.get("system_info", {}).get("os", "Unknown"),
                    "file_path": str(file),
                    "file_size_bytes": stat.st_size,
                    "summary": data.get("summary", {}),
                    "total_suspicious_items": (
                        len(data.get("suspicious_items", [])) 
                        if "suspicious_items" in data 
                        else data.get("summary", {}).get("total_suspicious_items", 0)
                    )
                })
            except Exception:
                continue
        return results

    def get_latest_snapshot(self) -> Optional[SecuritySnapshot]:
        """Returns the most recent snapshot if available."""
        snapshots = self.list_snapshots(limit=1)
        if not snapshots:
            return None
        latest_id = snapshots[0].get("snapshot_id")
        return self.load_snapshot(latest_id) if latest_id else None

    def prune_snapshots(self, max_snapshots: Optional[int] = 30, max_age_days: Optional[int] = 30) -> Dict[str, Any]:
        """
        Enforces retention policy:
        1. Deletes snapshots older than max_age_days.
        2. Enforces max_snapshots ceiling, pruning oldest entries first.
        """
        all_files = sorted(self.base_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
        deleted_ids: List[str] = []
        now_ts = time.time()

        # Step 1: Age-based pruning
        remaining_files = []
        if max_age_days is not None and max_age_days > 0:
            cutoff_seconds = max_age_days * 86400
            for file in all_files:
                try:
                    file_age = now_ts - file.stat().st_mtime
                    if file_age > cutoff_seconds:
                        snap_id = file.stem.replace("snapshot_", "")
                        file.unlink()
                        deleted_ids.append(snap_id)
                    else:
                        remaining_files.append(file)
                except Exception:
                    remaining_files.append(file)
        else:
            remaining_files = all_files

        # Step 2: Count-based ceiling pruning
        if max_snapshots is not None and max_snapshots > 0:
            if len(remaining_files) > max_snapshots:
                excess_files = remaining_files[max_snapshots:]
                for file in excess_files:
                    try:
                        snap_id = file.stem.replace("snapshot_", "")
                        file.unlink()
                        deleted_ids.append(snap_id)
                    except Exception:
                        pass
                remaining_files = remaining_files[:max_snapshots]

        return {
            "pruned_count": len(deleted_ids),
            "deleted_snapshots": deleted_ids,
            "remaining_count": len(remaining_files)
        }

    def get_storage_stats(self) -> Dict[str, Any]:
        """Returns aggregate storage metrics."""
        files = list(self.base_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        latest = self.list_snapshots(limit=1)
        return {
            "total_snapshots": len(files),
            "storage_dir": str(self.base_dir),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "latest_snapshot_id": latest[0]["snapshot_id"] if latest else None,
            "latest_timestamp": latest[0]["timestamp"] if latest else None
        }

    def diff_snapshots(self, base_id: Optional[str], target_id: str):
        """
        Loads base and target snapshots and computes structural security diff.
        """
        from agent.security.diff import compute_security_diff
        target = self.load_snapshot(target_id)
        if not target:
            return None
        base = self.load_snapshot(base_id) if base_id else None
        return compute_security_diff(target, base)

    def diff_latest_against_previous(self):
        """
        Compares the most recent snapshot against its predecessor.
        If only one snapshot exists, diffs it against None (baseline view).
        """
        from agent.security.diff import compute_security_diff
        snaps = self.list_snapshots(limit=2)
        if not snaps:
            return None
        target = self.load_snapshot(snaps[0]["snapshot_id"])
        if not target:
            return None
        base = self.load_snapshot(snaps[1]["snapshot_id"]) if len(snaps) > 1 else None
        return compute_security_diff(target, base)


