import sys
from static_analyzer import StaticAnalyzer
from yara_engine import YaraEngine
from behavioral_emulator import BehavioralEmulator
from ioc_extractor import IocExtractor
from mitre_mapper import MitreMapper
from threat_scorer import ThreatScorer
from reporter import Reporter
from samples_generator import get_preset_samples, get_preset_sample_by_id

def test_full_pipeline():
    print("[+] Testing Malware Threat Analysis Pipeline...")
    
    # Self-contained synthetic test payload for analytical pipeline verification
    content = b"MZ\x90\0\x03\0\0\0vssadmin.exe delete shadows /all /quiet bcdedit /set {default} recoveryenabled No CryptEncrypt VirtualAllocEx WriteProcessMemory CreateRemoteThread 185.220.101.4 UPX0 UPX1"
    filename = "test_synthetic_payload.bin"
    
    # 1. Static Analyzer
    sa = StaticAnalyzer()
    static_res = sa.analyze(content, filename)
    assert static_res["hashes"]["md5"] is not None
    print("  [x] Static Analyzer passed.")
    
    # 2. YARA Engine
    ye = YaraEngine()
    yara_res = ye.scan(content)
    assert yara_res["match_count"] >= 1
    print(f"  [x] YARA Engine passed ({yara_res['match_count']} matches).")
    
    # 3. Behavioral Emulator
    be = BehavioralEmulator()
    behavioral_res = be.emulate_execution(content, {"filename": filename}, static_res)
    assert len(behavioral_res["api_call_stream"]) > 0
    print("  [x] Behavioral Emulator passed.")
    
    # 4. IOC Extractor
    ie = IocExtractor()
    ioc_res = ie.extract(content, static_res, behavioral_res)
    assert ioc_res["total_extracted"] > 0
    print(f"  [x] IOC Extractor passed ({ioc_res['total_extracted']} IOCs).")
    
    # 5. MITRE Mapper
    mm = MitreMapper()
    mitre_res = mm.map_analysis(static_res, yara_res, behavioral_res, ioc_res)
    assert mitre_res["total_mapped_techniques"] > 0
    print(f"  [x] MITRE Mapper passed ({mitre_res['total_mapped_techniques']} techniques).")
    
    # 6. Threat Scorer
    ts = ThreatScorer()
    threat_res = ts.calculate_score(static_res, yara_res, behavioral_res, ioc_res, mitre_res)
    assert threat_res["threat_score"] > 50
    print(f"  [x] Threat Scorer passed (Score: {threat_res['threat_score']}, Verdict: {threat_res['verdict']}).")
    
    # 7. Reporter
    rep = Reporter()
    stix = rep.generate_stix_21(filename, static_res, threat_res, ioc_res, mitre_res)
    assert stix["type"] == "bundle"
    html = rep.generate_html(filename, static_res, threat_res, yara_res, behavioral_res, ioc_res, mitre_res)
    assert "Analysis Report" in html
    print("  [x] Reporter passed.")

    # 8. Host Scanner & Vulnerability Auditor
    from host_scanner import HostScanner
    hs = HostScanner()
    assessment = hs.auto_assess_system()
    assert "health_score" in assessment
    assert len(assessment["host_info"]["hostname"]) > 0
    assert len(assessment["threat_forecast"]) > 0
    print(f"  [x] Host Scanner & Vulnerability Auditor passed (Host: {assessment['host_info']['hostname']}, Health: {assessment['health_score']}/100).")
    
    # 9. Pasha 2.0 Local Agent & Snapshot Engine
    from agent.main import run_local_scan
    snapshot = run_local_scan(save_to_store=True)
    assert snapshot.snapshot_id is not None
    assert len(snapshot.collector_reports) >= 6
    assert "processes" in snapshot.collector_reports
    print(f"  [x] Pasha 2.0 Local Agent passed (Snapshot: {snapshot.snapshot_id}, Collectors: {len(snapshot.collector_reports)}).")

    print("[SUCCESS] All pipeline & host security tests passed cleanly!")

if __name__ == "__main__":
    test_full_pipeline()
