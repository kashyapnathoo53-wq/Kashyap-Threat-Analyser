import os
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from agent.models.snapshot import SecuritySnapshot, CollectorReport, ProcessItem
from agent.security.suspicious_items import (
    evaluate_process_heuristics,
    evaluate_persistence_heuristics,
    evaluate_service_heuristics,
    evaluate_scheduled_task_heuristics,
    evaluate_network_heuristics,
    evaluate_file_heuristics,
)
from agent.collectors.processes import collect_processes
from agent.collectors.persistence import collect_persistence
from agent.collectors.services import collect_services
from agent.collectors.scheduled_tasks import collect_scheduled_tasks
from agent.collectors.network import collect_network_connections
from agent.collectors.files import collect_security_files
from agent.collectors.browser import collect_browser_info
from agent.storage.snapshot_store import SnapshotStore
from agent.communication.protocol import (
    AgentMessage,
    MessageType,
    create_response,
    create_error_response,
)

class TestPashaLocalAgent(unittest.TestCase):

    def test_heuristics_process(self):
        # Normal process
        is_sus, reasons = evaluate_process_heuristics("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "notepad.exe")
        self.assertFalse(is_sus)

        # Suspicious Temp execution
        is_sus, reasons = evaluate_process_heuristics("malware.exe", "C:\\Users\\Victim\\AppData\\Local\\Temp\\malware.exe", "malware.exe")
        self.assertTrue(is_sus)
        self.assertTrue(any("temporary directory" in r for r in reasons))

        # Suspicious encoded command
        is_sus, reasons = evaluate_process_heuristics("powershell.exe", "C:\\Windows\\System32\\powershell.exe", "powershell.exe -enc AAAAAvssadminAAAA")
        self.assertTrue(is_sus)
        self.assertTrue(any("Encoded PowerShell" in r for r in reasons))

    def test_heuristics_persistence(self):
        is_sus, reasons = evaluate_persistence_heuristics("GoodApp", "HKCU\\Run", "C:\\Program Files\\GoodApp\\app.exe")
        self.assertFalse(is_sus)

        is_sus, reasons = evaluate_persistence_heuristics("BadApp", "HKCU\\Run", "wscript.exe C:\\Users\\User\\AppData\\Local\\Temp\\drop.vbs")
        self.assertTrue(is_sus)
        self.assertTrue(any("script file" in r or "temporary directory" in r for r in reasons))

    def test_heuristics_file(self):
        # Clean file
        is_sus, reasons = evaluate_file_heuristics("document.pdf", "C:\\Users\\User\\Documents\\document.pdf", 1024)
        self.assertFalse(is_sus)

        # Double extension disguise
        is_sus, reasons = evaluate_file_heuristics("Invoice.pdf.exe", "C:\\Users\\User\\Downloads\\Invoice.pdf.exe", 2048)
        self.assertTrue(is_sus)
        self.assertTrue(any("double" in r.lower() for r in reasons))

    def test_heuristics_network(self):
        is_sus, reasons = evaluate_network_heuristics("93.184.216.34", 443, "chrome.exe")
        self.assertFalse(is_sus)

        # Shell establishing outbound socket
        is_sus, reasons = evaluate_network_heuristics("194.26.29.112", 4444, "powershell.exe")
        self.assertTrue(is_sus)
        self.assertTrue(any("port (4444)" in r for r in reasons))

    def test_collect_persistence(self):
        items, report = collect_persistence()
        self.assertIsInstance(report, CollectorReport)
        self.assertEqual(report.status, "SUCCESS")
        self.assertIsInstance(items, list)

    def test_collect_services(self):
        items, report = collect_services()
        self.assertIsInstance(report, CollectorReport)
        self.assertIn(report.status, ["SUCCESS", "PARTIAL"])
        self.assertIsInstance(items, list)

    def test_collect_scheduled_tasks(self):
        items, report = collect_scheduled_tasks()
        self.assertIsInstance(report, CollectorReport)
        self.assertIn(report.status, ["SUCCESS", "PARTIAL"])
        self.assertIsInstance(items, list)

    def test_collect_network(self):
        items, report = collect_network_connections({4: "System"})
        self.assertIsInstance(report, CollectorReport)
        self.assertEqual(report.status, "SUCCESS")
        self.assertIsInstance(items, list)

    def test_collect_browser(self):
        items, report = collect_browser_info()
        self.assertIsInstance(report, CollectorReport)
        self.assertEqual(report.status, "SUCCESS")
        self.assertIsInstance(items, list)

    def test_snapshot_store(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SnapshotStore(tmpdir)
            snap = SecuritySnapshot(
                snapshot_id="test_snap_001",
                host_id="test-host-id-12345",
                os_version="Windows 11 Test",
                summary={"total_processes": 10},
                processes=[ProcessItem(pid=100, name="test.exe")]
            )
            saved_path = store.save_snapshot(snap)
            self.assertTrue(os.path.exists(saved_path))

            loaded = store.load_snapshot("test_snap_001")
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.snapshot_id, "test_snap_001")
            self.assertEqual(loaded.host_id, "test-host-id-12345")
            self.assertEqual(len(loaded.processes), 1)

            listed = store.list_snapshots()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["snapshot_id"], "test_snap_001")

            # Test deletion
            deleted = store.delete_snapshot("test_snap_001")
            self.assertTrue(deleted)
            self.assertIsNone(store.load_snapshot("test_snap_001"))
            self.assertEqual(len(store.list_snapshots()), 0)

    def test_snapshot_normalization_and_aliases(self):
        from agent.models.snapshot import SuspiciousSummaryItem, PersistenceItem, NetworkConnectionItem, FileItem, BrowserInfo
        snap = SecuritySnapshot(
            snapshot_id="snap_norm_001",
            host_id="host-guid-999",
            os_version="Windows 11 64-bit",
            snapshot_metadata={"schema_version": "2.0.0", "scan_duration_ms": 120.5},
            processes=[ProcessItem(pid=4, name="System")],
            persistence_items=[PersistenceItem(name="RunTest", location="HKCU\\Run", command="calc.exe", type="Registry RunKey")],
            network_connections=[NetworkConnectionItem(local_addr="127.0.0.1", local_port=8000, pid=4)],
            scanned_files=[FileItem(path="C:\\test.exe", name="test.exe", category="Temp", extension=".exe")],
            browser_info=[BrowserInfo(name="Edge", is_installed=True)],
            suspicious_items=[SuspiciousSummaryItem(category="process", name="bad.exe", target="C:\\bad.exe", reasons=["Temp execution"])]
        )

        # Check normalization
        self.assertEqual(snap.host_id, "host-guid-999")
        self.assertEqual(snap.os_version, "Windows 11 64-bit")
        self.assertEqual(len(snap.suspicious_items), 1)
        self.assertEqual(snap.suspicious_items[0].name, "bad.exe")

        # Check alias property access
        self.assertEqual(len(snap.persistence), 1)
        self.assertEqual(len(snap.network), 1)
        self.assertEqual(len(snap.files), 1)
        self.assertEqual(len(snap.browser), 1)

    def test_snapshot_retention_and_pruning(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SnapshotStore(tmpdir)
            # Create 5 snapshots
            for i in range(5):
                s = SecuritySnapshot(
                    snapshot_id=f"snap_ret_{i:03d}",
                    summary={"total_processes": i}
                )
                store.save_snapshot(s, auto_prune=False)

            self.assertEqual(len(store.list_snapshots()), 5)

            # Prune to max 3
            result = store.prune_snapshots(max_snapshots=3, max_age_days=None)
            self.assertEqual(result["pruned_count"], 2)
            self.assertEqual(result["remaining_count"], 3)
            self.assertEqual(len(store.list_snapshots()), 3)

            # Check storage stats
            stats = store.get_storage_stats()
            self.assertEqual(stats["total_snapshots"], 3)
            self.assertIsNotNone(stats["latest_snapshot_id"])

    def test_communication_protocol(self):
        resp = create_response(MessageType.STATUS_RESPONSE, {"status": "ok", "version": "2.0.0"}, request_id="req-1")
        self.assertEqual(resp.type, MessageType.STATUS_RESPONSE)
        self.assertEqual(resp.payload["status"], "ok")
        self.assertIsNone(resp.error)

        err_resp = create_error_response("Access Denied", request_id="req-2")
        self.assertEqual(err_resp.type, MessageType.ERROR_RESPONSE)
        self.assertEqual(err_resp.error, "Access Denied")

    def test_agent_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test status
        status_resp = client.get("/api/agent/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertEqual(status_data["status"], "online")
        self.assertEqual(status_data["agent_version"], "2.0.0")
        self.assertIn("machine_id", status_data)

        # 2. Test snapshots list
        list_resp = client.get("/api/agent/snapshots")
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.json()
        self.assertIn("snapshots", list_data)
        self.assertIn("total", list_data)

        # 3. Test latest snapshot if any exists
        if list_data["total"] > 0:
            latest_resp = client.get("/api/agent/snapshots/latest")
            self.assertEqual(latest_resp.status_code, 200)
            latest_data = latest_resp.json()
            self.assertIn("snapshot_id", latest_data)
            self.assertIn("processes", latest_data)

            # 4. Test get by ID
            snap_id = latest_data["snapshot_id"]
            get_resp = client.get(f"/api/agent/snapshots/{snap_id}")
            self.assertEqual(get_resp.status_code, 200)
            self.assertEqual(get_resp.json()["snapshot_id"], snap_id)

        # 5. Test 404 on nonexistent snapshot
        bad_resp = client.get("/api/agent/snapshots/nonexistent_snap_9999")
        self.assertEqual(bad_resp.status_code, 404)

        # 6. Test prune endpoint
        prune_resp = client.post("/api/agent/snapshots/prune", json={"max_snapshots": 50, "max_age_days": 60})
        self.assertEqual(prune_resp.status_code, 200)
        self.assertEqual(prune_resp.json()["status"], "success")

    def test_security_diff_engine(self):
        from agent.security.diff import compute_security_diff
        from agent.models.snapshot import (
            ProcessItem, PersistenceItem, ServiceItem,
            ScheduledTaskItem, NetworkConnectionItem, FileItem
        )

        # Baseline snapshot
        base = SecuritySnapshot(
            snapshot_id="snap_base_001",
            timestamp="2026-09-25T12:00:00+00:00",
            processes=[
                ProcessItem(pid=1000, name="explorer.exe", path="C:\\Windows\\explorer.exe"),
                ProcessItem(pid=2000, name="old_app.exe", path="C:\\Program Files\\old_app.exe")
            ],
            persistence=[
                PersistenceItem(name="GoodRun", location="HKCU\\Run", command="good.exe", type="Registry RunKey")
            ],
            services=[
                ServiceItem(name="SafeService", display_name="Safe", binary_path="C:\\Windows\\system32\\safe.exe", start_mode="Auto")
            ],
            scheduled_tasks=[
                ScheduledTaskItem(name="SafeTask", path="\\", action="C:\\Windows\\system32\\safe.exe")
            ],
            network=[
                NetworkConnectionItem(proto="TCP", local_addr="127.0.0.1", local_port=80, state="LISTENING", pid=1000)
            ],
            files=[
                FileItem(path="C:\\Users\\User\\Downloads\\doc.pdf", name="doc.pdf", category="Downloads", extension=".pdf", sha256="aaa")
            ]
        )

        # Target snapshot with suspicious additions and a modification
        target = SecuritySnapshot(
            snapshot_id="snap_target_002",
            timestamp="2026-09-25T12:05:00+00:00",
            processes=[
                ProcessItem(pid=1000, name="explorer.exe", path="C:\\Windows\\explorer.exe"),
                # New suspicious process
                ProcessItem(
                    pid=3000,
                    name="powershell.exe",
                    path="C:\\Windows\\System32\\powershell.exe",
                    cmdline="powershell.exe -enc AAAAAvssadminAAAA",
                    is_suspicious=True,
                    suspicious_reasons=["Encoded PowerShell invocation"]
                )
            ],
            persistence=[
                PersistenceItem(name="GoodRun", location="HKCU\\Run", command="good.exe", type="Registry RunKey"),
                # New persistence mechanism
                PersistenceItem(name="BadStartup", location="HKCU\\Run", command="C:\\Temp\\drop.exe", type="Registry RunKey")
            ],
            services=[
                # Modified service binary
                ServiceItem(name="SafeService", display_name="Safe", binary_path="C:\\Users\\Default\\AppData\\hacked.exe", start_mode="Auto")
            ],
            scheduled_tasks=[
                ScheduledTaskItem(name="SafeTask", path="\\", action="C:\\Windows\\system32\\safe.exe"),
                # New task
                ScheduledTaskItem(name="EvilTask", path="\\", action="cmd.exe /c start evil.exe", is_suspicious=True, suspicious_reasons=["cmd execution"])
            ],
            network=[
                NetworkConnectionItem(proto="TCP", local_addr="127.0.0.1", local_port=80, state="LISTENING", pid=1000),
                # New connection to suspicious port 4444
                NetworkConnectionItem(proto="TCP", local_addr="192.168.1.5", local_port=54000, remote_addr="1.2.3.4", remote_port=4444, state="ESTABLISHED", pid=3000, process_name="powershell.exe")
            ],
            files=[
                FileItem(path="C:\\Users\\User\\Downloads\\doc.pdf", name="doc.pdf", category="Downloads", extension=".pdf", sha256="aaa"),
                # New file with double extension
                FileItem(path="C:\\Users\\User\\Downloads\\Invoice.pdf.exe", name="Invoice.pdf.exe", category="Downloads", extension=".exe", is_suspicious=True, suspicious_reasons=["Double extension disguise"])
            ]
        )

        diff = compute_security_diff(target_snapshot=target, base_snapshot=base)

        self.assertEqual(diff.base_snapshot_id, "snap_base_001")
        self.assertEqual(diff.target_snapshot_id, "snap_target_002")
        self.assertEqual(diff.time_delta_seconds, 300.0)

        # Check category diffs
        self.assertEqual(diff.categories["processes"].added_count, 1)
        self.assertEqual(diff.categories["processes"].removed_count, 1)  # old_app.exe was removed
        self.assertEqual(diff.categories["processes"].security_relevant_count, 1)

        self.assertEqual(diff.categories["persistence"].added_count, 1)
        self.assertEqual(diff.categories["persistence"].security_relevant_count, 1)

        self.assertEqual(diff.categories["services"].modified_count, 1)
        self.assertEqual(diff.categories["services"].security_relevant_count, 1)

        self.assertEqual(diff.categories["scheduled_tasks"].added_count, 1)
        self.assertEqual(diff.categories["scheduled_tasks"].security_relevant_count, 1)

        self.assertEqual(diff.categories["network"].added_count, 1)
        self.assertEqual(diff.categories["network"].security_relevant_count, 1)

        self.assertEqual(diff.categories["files"].added_count, 1)
        self.assertEqual(diff.categories["files"].security_relevant_count, 1)

        # Summary assertions
        self.assertGreater(diff.summary["total_security_relevant"], 0)
        self.assertIn("CRITICAL", diff.summary["verdict"])

    def test_security_diff_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test GET /api/agent/diff/latest
        r_latest = client.get("/api/agent/diff/latest")
        self.assertEqual(r_latest.status_code, 200)
        diff_data = r_latest.json()
        self.assertIn("diff_id", diff_data)
        self.assertIn("categories", diff_data)
        self.assertIn("summary", diff_data)
        self.assertIn("verdict", diff_data["summary"])

        # 2. Test GET /api/agent/diff with arbitrary target_id
        target_id = diff_data["target_snapshot_id"]
        r_diff = client.get(f"/api/agent/diff?target_id={target_id}")
        self.assertEqual(r_diff.status_code, 200)
        self.assertEqual(r_diff.json()["target_snapshot_id"], target_id)

        # 3. Test 404 on nonexistent target
        r_bad = client.get("/api/agent/diff?target_id=snap_not_found_0000")
        self.assertEqual(r_bad.status_code, 404)

    def test_candidate_detection_and_priority_scoring(self):
        from agent.models.snapshot import ProcessItem, PersistenceItem, NetworkConnectionItem, FileItem
        from agent.security.candidate_detector import detect_candidates_from_snapshot

        snap = SecuritySnapshot(
            snapshot_id="snap_cand_test_01",
            processes=[
                ProcessItem(
                    pid=4444,
                    name="powershell.exe",
                    cmdline="powershell.exe -enc AAAAA -w hidden",
                    is_suspicious=True,
                    suspicious_reasons=["Encoded PowerShell Command Execution", "Hidden Window Process Spawning"]
                )
            ],
            persistence=[
                PersistenceItem(
                    name="EvilStartup",
                    location="HKCU\\Run",
                    command="wscript.exe C:\\Users\\User\\AppData\\Local\\Temp\\drop.vbs",
                    type="Registry RunKey",
                    is_suspicious=True,
                    suspicious_reasons=["Persistence executes raw script file (.vbs)", "Persistence entry points to temporary directory (Temp)"]
                )
            ],

            files=[
                FileItem(
                    path="C:\\Users\\User\\Downloads\\Invoice.pdf.exe",
                    name="Invoice.pdf.exe",
                    category="Downloads",
                    extension=".exe",
                    is_suspicious=True,
                    suspicious_reasons=["Executable disguised with double extension (.pdf.exe)"]
                )
            ],
            network=[
                NetworkConnectionItem(
                    proto="TCP",
                    local_addr="192.168.1.10",
                    local_port=52000,
                    remote_addr="185.220.101.5",
                    remote_port=4444,
                    state="ESTABLISHED",
                    pid=4444,
                    process_name="powershell.exe",
                    is_suspicious=True,
                    suspicious_reasons=["Command shell process established connection to suspicious port (4444)"]
                )
            ]
        )

        candidates = detect_candidates_from_snapshot(snap)
        self.assertEqual(len(candidates), 4)

        # Priority assertions
        for c in candidates:
            self.assertGreaterEqual(c.priority_score, 50)
            self.assertEqual(c.status, "DISCOVERED")
            self.assertEqual(c.snapshot_id, "snap_cand_test_01")

        # Sorted descending
        scores = [c.priority_score for c in candidates]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_candidate_queue_lifecycle(self):
        import tempfile
        from agent.models.candidate import SuspiciousCandidate, CandidateStatus
        from agent.storage.candidate_queue import CandidateQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue_file = os.path.join(tmpdir, "test_queue.json")
            q = CandidateQueue(queue_file)

            c1 = SuspiciousCandidate(
                candidate_id="cand_1",
                snapshot_id="snap_1",
                category="process",
                name="powershell.exe",
                cmdline="powershell.exe -enc ABC",
                priority_score=75,
                heuristics_matched=["Encoded command"]
            )
            c2 = SuspiciousCandidate(
                candidate_id="cand_2",
                snapshot_id="snap_1",
                category="file",
                name="Invoice.pdf.exe",
                target_path="C:\\Downloads\\Invoice.pdf.exe",
                priority_score=85,
                heuristics_matched=["Double extension"]
            )

            # Add to queue
            added = q.add_candidates([c1, c2])
            self.assertEqual(len(added), 2)
            self.assertEqual(len(q.list_candidates()), 2)

            # Test Next Queued Candidate (should be c2 because score 85 > 75)
            next_cand = q.get_next_queued_candidate()
            self.assertIsNotNone(next_cand)
            self.assertEqual(next_cand.candidate_id, "cand_2")

            # Status transition
            updated = q.update_status("cand_2", "ANALYZING")
            self.assertEqual(updated.status, CandidateStatus.ANALYZING)

            updated = q.update_status("cand_2", "ANALYZED", report_id="rep_sha256_mock")
            self.assertEqual(updated.status, CandidateStatus.ANALYZED)
            self.assertEqual(updated.analysis_report_id, "rep_sha256_mock")

            # Deduplication: re-adding c1 should update rather than duplicate
            c1_dup = SuspiciousCandidate(
                candidate_id="cand_1_dup",
                snapshot_id="snap_2",
                category="process",
                name="powershell.exe",
                cmdline="powershell.exe -enc ABC",
                priority_score=90,
                heuristics_matched=["Encoded command", "Ransomware flag"]
            )
            re_added = q.add_candidates([c1_dup])
            self.assertEqual(len(q.list_candidates()), 2)  # Still 2 items!
            c1_fetched = q.get_candidate("cand_1")
            self.assertEqual(c1_fetched.priority_score, 90)  # Score updated

            # Summary metrics
            summary = q.get_summary()
            self.assertEqual(summary.total_candidates, 2)
            self.assertEqual(summary.highest_priority_score, 90)

            # Deletion
            deleted = q.delete_candidate("cand_1")
            self.assertTrue(deleted)
            self.assertEqual(len(q.list_candidates()), 1)

    def test_candidate_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Trigger detection
        det_resp = client.post("/api/agent/candidates/detect", json={"auto_queue": True})
        self.assertEqual(det_resp.status_code, 200)
        det_data = det_resp.json()
        self.assertEqual(det_data["status"], "success")
        self.assertIn("candidates", det_data)

        # 2. List candidates
        list_resp = client.get("/api/agent/candidates")
        self.assertEqual(list_resp.status_code, 200)
        self.assertIn("candidates", list_resp.json())

        # 3. Summary
        sum_resp = client.get("/api/agent/candidates/summary")
        self.assertEqual(sum_resp.status_code, 200)
        self.assertIn("total_candidates", sum_resp.json())

        # 4. If candidates exist, test ID lookup and status update
        candidates = list_resp.json()["candidates"]
        if candidates:
            c_id = candidates[0]["candidate_id"]
            get_resp = client.get(f"/api/agent/candidates/{c_id}")
            self.assertEqual(get_resp.status_code, 200)
            self.assertEqual(get_resp.json()["candidate_id"], c_id)

            patch_resp = client.patch(
                f"/api/agent/candidates/{c_id}/status",
                json={"status": "QUEUED"}
            )
            self.assertEqual(patch_resp.status_code, 200)
            self.assertEqual(patch_resp.json()["candidate"]["status"], "QUEUED")

    def test_investigation_orchestrator(self):
        import tempfile
        from main import run_full_analysis
        from agent.models.candidate import SuspiciousCandidate, CandidateStatus
        from agent.storage.candidate_queue import CandidateQueue
        from agent.orchestration.investigator import InvestigationOrchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            queue_file = os.path.join(tmpdir, "test_orch_queue.json")
            q = CandidateQueue(queue_file)
            mock_store = {}
            orch = InvestigationOrchestrator(
                candidate_queue=q,
                analysis_fn=run_full_analysis,
                analysis_store=mock_store
            )

            # Add a candidate with suspicious command line
            cand = SuspiciousCandidate(
                candidate_id="cand_test_orch_01",
                snapshot_id="snap_test",
                category="process",
                name="powershell.exe",
                cmdline="powershell.exe -enc AAAAAvssadminAAAA",
                priority_score=85,
                heuristics_matched=["Encoded PowerShell invocation", "Ransomware flag"]
            )
            q.add_candidates([cand])

            # Investigate
            res = orch.investigate_candidate("cand_test_orch_01")
            self.assertIsNotNone(res)
            self.assertEqual(res["status"], "success")
            self.assertEqual(res["candidate_id"], "cand_test_orch_01")
            self.assertIn("report_id", res)
            self.assertGreater(res["threat_score"], 0)
            self.assertIn("verdict", res)

            # Candidate in queue should now be ANALYZED with linked report_id
            updated_cand = q.get_candidate("cand_test_orch_01")
            self.assertEqual(updated_cand.status, CandidateStatus.ANALYZED)
            self.assertEqual(updated_cand.analysis_report_id, res["report_id"])

            # Verify report retrieval
            report = orch.get_candidate_report("cand_test_orch_01")
            self.assertIsNotNone(report)
            self.assertEqual(report["report_id"], res["report_id"])

    def test_investigation_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Detect candidates
        det = client.post("/api/agent/candidates/detect", json={"auto_queue": True})
        self.assertEqual(det.status_code, 200)

        # 2. Investigate next candidate
        inv_next = client.post("/api/agent/investigate/next")
        # May be 200 if candidate ready, or 404 if queue empty
        if inv_next.status_code == 200:
            inv_data = inv_next.json()
            self.assertEqual(inv_data["status"], "success")
            self.assertIn("report_id", inv_data)
            self.assertIn("threat_score", inv_data)
            cand_id = inv_data["candidate_id"]

            # 3. Retrieve report via candidate ID
            rep_resp = client.get(f"/api/agent/candidates/{cand_id}/report")
            self.assertEqual(rep_resp.status_code, 200)
            self.assertEqual(rep_resp.json()["report_id"], inv_data["report_id"])

        # 4. Test 404 on nonexistent candidate investigation
        bad_inv = client.post("/api/agent/investigate/nonexistent_cand_9999")
        self.assertEqual(bad_inv.status_code, 404)

    def test_evidence_correlation_and_attack_story(self):
        from agent.models.candidate import SuspiciousCandidate
        from agent.security.correlation import correlate_evidence

        cand = SuspiciousCandidate(
            candidate_id="cand_corr_01",
            snapshot_id="snap_corr_01",
            category="process",
            name="ransomware.exe",
            target_path="C:\\Temp\\ransomware.exe",
            cmdline="ransomware.exe -vssadmin delete shadows",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            priority_score=90,
            heuristics_matched=["Ransomware Shadow Copy Deletion", "Process in Temp"]
        )

        mock_report = {
            "report_id": "rep_corr_01",
            "sample_name": "ransomware.exe",
            "static_analysis": {
                "hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                "entropy": {"value": 7.82}
            },
            "yara_scan": {
                "matches": [
                    {"rule": "Ransomware_WannaCry_Strings", "severity": "CRITICAL", "description": "Known ransomware match"}
                ]
            },
            "behavioral_analysis": {
                "registry_activity": {
                    "run_keys": [{"key": "HKCU\\Run", "path": "HKCU\\Run", "value": "C:\\Temp\\ransomware.exe"}]
                },
                "filesystem_activity": {
                    "dropped_files": [{"filename": "HOW_TO_DECRYPT.txt", "path": "C:\\HOW_TO_DECRYPT.txt", "size_bytes": 1024, "is_executable": False}]
                },
                "network_activity": {
                    "beacons": [{"ip": "185.220.101.5", "port": 4444, "proto": "TCP"}]
                }
            },
            "ioc_extraction": {
                "iocs": {
                    "ipv4": ["185.220.101.5"]
                }
            },
            "mitre_mapping": {
                "techniques": [
                    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
                    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
                ]
            },
            "threat_scoring": {
                "threat_score": 95,
                "verdict": "MALICIOUS"
            }
        }

        story = correlate_evidence(candidate=cand, report=mock_report)

        self.assertIsNotNone(story)
        self.assertEqual(story.verdict, "MALICIOUS")
        self.assertEqual(story.threat_score, 95)
        self.assertGreaterEqual(story.confidence_score, 80)
        self.assertIn("ransomware.exe", story.title)
        self.assertIn("95/100", story.summary_narrative)

        # Graph verification
        node_types = {n.type for n in story.graph.nodes}
        self.assertIn("process", node_types)
        self.assertIn("file", node_types)
        self.assertIn("yara", node_types)
        self.assertIn("persistence", node_types)
        self.assertIn("network", node_types)
        self.assertIn("mitre", node_types)

        # Edges verification
        relations = {e.relation for e in story.graph.edges}
        self.assertIn("MATCHED_SIGNATURE", relations)
        self.assertIn("REGISTERED_PERSISTENCE", relations)
        self.assertIn("COMMUNICATED_WITH", relations)
        self.assertIn("EXEMPLIFIES_TECHNIQUE", relations)

        # Phases verification
        self.assertGreaterEqual(len(story.phases), 4)

    def test_attack_story_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test GET /api/agent/attack-story/latest
        r_latest = client.get("/api/agent/attack-story/latest")
        if r_latest.status_code == 200:
            story_data = r_latest.json()
            self.assertIn("story_id", story_data)
            self.assertIn("graph", story_data)
            self.assertIn("nodes", story_data["graph"])
            self.assertIn("edges", story_data["graph"])
            self.assertIn("phases", story_data)
            self.assertIn("summary_narrative", story_data)

            # 2. Test specific candidate story
            cand_id = story_data["candidate_id"]
            r_cand = client.get(f"/api/agent/attack-story/{cand_id}")
            self.assertEqual(r_cand.status_code, 200)
            self.assertEqual(r_cand.json()["candidate_id"], cand_id)

        # 3. Test 404 on nonexistent candidate story
        r_bad = client.get("/api/agent/attack-story/nonexistent_cand_9999")
        self.assertEqual(r_bad.status_code, 404)

    def test_security_timeline_reconstruction(self):
        from agent.models.candidate import SuspiciousCandidate
        from agent.security.timeline import reconstruct_security_timeline

        cand = SuspiciousCandidate(
            candidate_id="cand_time_test",
            snapshot_id="snap_time_test_01",
            category="process",
            name="evil_stealer.exe",
            target_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\evil_stealer.exe",
            sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
            discovered_at="2026-09-26T07:00:00+00:00",
            priority_score=85,
            heuristics_matched=["Executed from temporary directory", "Network connection to untrusted host"],
            status="ANALYZED"
        )

        mock_report = {
            "report_id": "rep_time_test",
            "behavioral_analysis": {
                "api_call_stream": [
                    {"timestamp": 0.2, "pid": 4120, "process": "evil_stealer.exe", "api": "VirtualAllocEx", "category": "Memory Injection", "arguments": "flProtect=PAGE_EXECUTE_READWRITE", "risk": "HIGH"},
                    {"timestamp": 0.8, "pid": 4120, "process": "evil_stealer.exe", "api": "URLDownloadToFileW", "category": "Network Download", "arguments": "szURL='http://c2.evil.com/drop.bin'", "risk": "HIGH"},
                ],
                "filesystem_activity": [
                    {"action": "CREATE_TEMP", "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\drop.bin", "size": "128 KB"}
                ],
                "registry_activity": [
                    {"action": "SET_VALUE", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persist", "value": "C:\\Temp\\evil_stealer.exe"}
                ],
                "network_activity": [
                    {"proto": "HTTP", "destination": "185.190.140.88:80", "domain": "c2.evil.com", "type": "Beacon", "bytes_sent": 256}
                ]
            },
            "mitre_mapping": {
                "techniques": [
                    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
                ]
            }
        }

        timeline = reconstruct_security_timeline(candidate=cand, report=mock_report)
        self.assertIsNotNone(timeline.timeline_id)
        self.assertEqual(timeline.target_id, "cand_time_test")
        self.assertGreater(timeline.total_events, 4)
        self.assertIn("api_call", timeline.event_counts_by_category)
        self.assertIn("detection", timeline.event_counts_by_category)
        self.assertIn("filesystem", timeline.event_counts_by_category)
        self.assertIn("network", timeline.event_counts_by_category)

        # Verify strict chronological order
        prev_rel = -1.0
        for ev in timeline.events:
            self.assertGreaterEqual(ev.relative_time_seconds, prev_rel)
            prev_rel = ev.relative_time_seconds

    def test_security_timeline_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test GET /api/agent/timeline/latest
        r_latest = client.get("/api/agent/timeline/latest")
        if r_latest.status_code == 200:
            t_data = r_latest.json()
            self.assertIn("timeline_id", t_data)
            self.assertIn("events", t_data)
            self.assertIn("total_events", t_data)
            self.assertIn("event_counts_by_category", t_data)
            self.assertIn("event_counts_by_severity", t_data)

            # 2. Test candidate timeline endpoint
            target_id = t_data["target_id"]
            if t_data["target_type"] == "candidate":
                r_cand = client.get(f"/api/agent/timeline/{target_id}")
                self.assertEqual(r_cand.status_code, 200)
                self.assertEqual(r_cand.json()["target_id"], target_id)

        # 3. Test 404 on nonexistent candidate timeline
        r_bad = client.get("/api/agent/timeline/nonexistent_cand_9999")
        self.assertEqual(r_bad.status_code, 404)

        # 4. Test 404 on nonexistent snapshot timeline
        r_bad_snap = client.get("/api/agent/timeline/snapshot/nonexistent_snap_9999")
        self.assertEqual(r_bad_snap.status_code, 404)

    def test_blast_radius_computation(self):
        from agent.models.candidate import SuspiciousCandidate
        from agent.security.blast_radius import compute_blast_radius

        cand = SuspiciousCandidate(
            candidate_id="cand_blast_test",
            snapshot_id="snap_blast_test_01",
            category="process",
            name="ransom_payload.exe",
            target_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\ransom_payload.exe",
            sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            discovered_at="2026-09-26T07:15:00+00:00",
            priority_score=90,
            heuristics_matched=["Known Ransomware Heuristics", "Suspicious Process Spawn"],
            status="ANALYZED",
            metadata={"pid": 5512, "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\ransom_payload.exe"}
        )

        mock_report = {
            "report_id": "rep_blast_test",
            "threat_scoring": {"threat_score": 85, "verdict": "MALICIOUS"},
            "behavioral_analysis": {
                "process_tree": {
                    "name": "ransom_payload.exe",
                    "pid": 5512,
                    "children": [
                        {"name": "vssadmin.exe", "pid": 6010, "children": []}
                    ]
                },
                "api_call_stream": [
                    {"api": "VirtualAllocEx", "process": "explorer.exe", "risk": "HIGH"}
                ],
                "filesystem_activity": [
                    {"action": "CREATE_TEMP", "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\note.txt", "size": "2 KB"}
                ],
                "registry_activity": [
                    {"action": "SET_VALUE", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Locker", "value": "C:\\Temp\\ransom_payload.exe"}
                ],
                "network_activity": [
                    {"proto": "HTTP", "destination": "45.33.32.156:8080", "domain": "c2.ransom-gate.com"}
                ]
            }
        }

        blast = compute_blast_radius(candidate=cand, report=mock_report)
        self.assertIsNotNone(blast.report_id)
        self.assertEqual(blast.candidate_id, "cand_blast_test")
        self.assertGreater(blast.blast_score, 50)
        self.assertIn(blast.scope_level, ["PERSISTED", "HOST_WIDE_COMPROMISE"])
        self.assertGreater(len(blast.affected_processes), 1)  # root + child or injected
        self.assertGreater(len(blast.affected_files), 0)
        self.assertGreater(len(blast.affected_registry), 0)
        self.assertGreater(len(blast.affected_network), 0)
        self.assertGreater(len(blast.containment_actions), 2)

        action_types = [a.action for a in blast.containment_actions]
        self.assertIn("TERMINATE", action_types)
        self.assertIn("QUARANTINE", action_types)
        self.assertIn("DELETE_KEY", action_types)
        self.assertIn("BLOCK_FIREWALL", action_types)

    def test_blast_radius_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test GET /api/agent/blast-radius/latest
        r_latest = client.get("/api/agent/blast-radius/latest")
        if r_latest.status_code == 200:
            b_data = r_latest.json()
            self.assertIn("report_id", b_data)
            self.assertIn("blast_score", b_data)
            self.assertIn("scope_level", b_data)
            self.assertIn("containment_actions", b_data)
            self.assertIn("affected_processes", b_data)

            # 2. Test candidate blast radius endpoint
            cand_id = b_data["candidate_id"]
            r_cand = client.get(f"/api/agent/blast-radius/{cand_id}")
            self.assertEqual(r_cand.status_code, 200)
            self.assertEqual(r_cand.json()["candidate_id"], cand_id)

        # 3. Test 404 on nonexistent candidate
        r_bad = client.get("/api/agent/blast-radius/nonexistent_cand_9999")
        self.assertEqual(r_bad.status_code, 404)

    def test_dual_threat_metrics_computation(self):
        from agent.models.candidate import SuspiciousCandidate
        from agent.security.metrics import evaluate_dual_metrics

        # Case 1: High Risk & High Confidence (WannaCry with YARA & C2 & Injection)
        cand_high = SuspiciousCandidate(
            candidate_id="cand_metric_test_01",
            snapshot_id="snap_m_01",
            category="process",
            name="wannacry_sim.exe",
            target_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\wannacry_sim.exe",
            sha256="222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
            discovered_at="2026-09-26T07:20:00+00:00",
            priority_score=95,
            heuristics_matched=["Known Ransomware Heuristics", "Suspicious Process Spawn"],
            status="ANALYZED"
        )
        report_high = {
            "report_id": "rep_metric_01",
            "threat_scoring": {"threat_score": 90, "verdict": "MALICIOUS"},
            "yara_scan": {
                "matches": [
                    {"rule": "Ransomware_WannaCry", "severity": "CRITICAL"},
                    {"rule": "ShadowCopy_Deletion", "severity": "HIGH"}
                ]
            },
            "static_analysis": {"entropy": {"value": 7.8}},
            "behavioral_analysis": {
                "api_call_stream": [
                    {"api": "VirtualAllocEx", "process": "lsass.exe", "risk": "HIGH"}
                ],
                "registry_activity": [
                    {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Wanna", "value": "C:\\Temp\\wannacry_sim.exe"}
                ],
                "network_activity": [
                    {"proto": "TCP", "destination": "185.190.140.88:445"}
                ]
            }
        }
        metrics_high = evaluate_dual_metrics(candidate=cand_high, report=report_high)
        self.assertIsNotNone(metrics_high.metric_id)
        self.assertGreaterEqual(metrics_high.risk_score, 75)
        self.assertGreaterEqual(metrics_high.confidence_score, 75)
        self.assertEqual(metrics_high.action_classification, "AUTOMATED_CONTAINMENT")
        self.assertEqual(metrics_high.risk_tier, "CRITICAL")
        self.assertIn(metrics_high.confidence_tier, ["HIGH_CONFIDENCE", "CONFIRMED"])

        # Case 2: Speculative / Unconfirmed Heuristic Candidate (No sandbox report)
        cand_spec = SuspiciousCandidate(
            candidate_id="cand_metric_test_02",
            snapshot_id="snap_m_02",
            category="file",
            name="strange_script.ps1",
            target_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\strange_script.ps1",
            discovered_at="2026-09-26T07:22:00+00:00",
            priority_score=80,
            heuristics_matched=["Suspicious Script Extension"],
            status="DISCOVERED"
        )
        metrics_spec = evaluate_dual_metrics(candidate=cand_spec, report=None)
        # Confidence must be capped to prevent false-positive automated containment
        self.assertLessEqual(metrics_spec.confidence_score, 50)
        self.assertEqual(metrics_spec.action_classification, "URGENT_ANALYST_REVIEW")

    def test_dual_threat_metrics_api_endpoints(self):
        from fastapi.testclient import TestClient
        from main import app
        client = TestClient(app)

        # 1. Test GET /api/agent/metrics/latest
        r_latest = client.get("/api/agent/metrics/latest")
        if r_latest.status_code == 200:
            m_data = r_latest.json()
            self.assertIn("metric_id", m_data)
            self.assertIn("risk_score", m_data)
            self.assertIn("confidence_score", m_data)
            self.assertIn("action_classification", m_data)
            self.assertIn("factors", m_data)

            # 2. Test candidate metrics endpoint
            cand_id = m_data["candidate_id"]
            r_cand = client.get(f"/api/agent/metrics/{cand_id}")
            self.assertEqual(r_cand.status_code, 200)
            self.assertEqual(r_cand.json()["candidate_id"], cand_id)

        # 3. Test 404 on nonexistent candidate
        r_bad = client.get("/api/agent/metrics/nonexistent_cand_9999")
        self.assertEqual(r_bad.status_code, 404)

if __name__ == "__main__":
    unittest.main()






