from typing import Dict, List, Any

class ThreatScorer:
    def __init__(self):
        pass

    def calculate_score(self, static_res: Dict[str, Any], yara_res: Dict[str, Any], behavioral_res: Dict[str, Any], ioc_res: Dict[str, Any], mitre_res: Dict[str, Any]) -> Dict[str, Any]:
        score_breakdown = {
            "static_score": 0,
            "yara_score": 0,
            "behavioral_score": 0,
            "ioc_score": 0,
            "mitre_score": 0
        }

        # 1. Static Score Weight (max 25 pts)
        file_info = static_res.get("file_info", {})
        pe_struct = static_res.get("pe_structure", {})
        
        if file_info.get("entropy", 0.0) > 7.1:
            score_breakdown["static_score"] += 10
        if pe_struct.get("is_packed"):
            score_breakdown["static_score"] += 8
        if pe_struct.get("import_count", 0) > 0:
            score_breakdown["static_score"] += min(10, pe_struct.get("import_count", 0) * 2)

        score_breakdown["static_score"] = min(25, score_breakdown["static_score"])

        # 2. YARA Score Weight (max 25 pts)
        yara_matches = yara_res.get("matches", [])
        for m in yara_matches:
            sev = m.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                score_breakdown["yara_score"] += 15
            elif sev == "HIGH":
                score_breakdown["yara_score"] += 10
            else:
                score_breakdown["yara_score"] += 5

        score_breakdown["yara_score"] = min(25, score_breakdown["yara_score"])

        # 3. Behavioral Score Weight (max 30 pts)
        api_stream = behavioral_res.get("api_call_stream", [])
        for api in api_stream:
            r = api.get("risk", "LOW")
            if r == "CRITICAL":
                score_breakdown["behavioral_score"] += 10
            elif r == "HIGH":
                score_breakdown["behavioral_score"] += 6
            elif r == "MEDIUM":
                score_breakdown["behavioral_score"] += 3

        score_breakdown["behavioral_score"] = min(30, score_breakdown["behavioral_score"])

        # 4. IOC Score Weight (max 10 pts)
        ioc_count = ioc_res.get("total_extracted", 0)
        score_breakdown["ioc_score"] = min(10, ioc_count * 2)

        # 5. MITRE TTP Score Weight (max 10 pts)
        mitre_count = mitre_res.get("total_mapped_techniques", 0)
        score_breakdown["mitre_score"] = min(10, mitre_count * 3)

        total_score = sum(score_breakdown.values())
        total_score = min(100, max(0, total_score))

        # Severity Classification
        if total_score >= 90:
            verdict = "MALICIOUS (CRITICAL RISK)"
            severity = "CRITICAL"
            color = "#ef4444"
        elif total_score >= 70:
            verdict = "MALICIOUS"
            severity = "HIGH"
            color = "#f97316"
        elif total_score >= 40:
            verdict = "SUSPICIOUS"
            severity = "MEDIUM"
            color = "#eab308"
        elif total_score >= 20:
            verdict = "LOW RISK"
            severity = "LOW"
            color = "#3b82f6"
        else:
            verdict = "CLEAN / BENIGN"
            severity = "CLEAN"
            color = "#22c55e"

        return {
            "threat_score": total_score,
            "verdict": verdict,
            "severity": severity,
            "color": color,
            "score_breakdown": score_breakdown,
            "risk_factors": [
                f"YARA Rule Hit Count: {len(yara_matches)}",
                f"Entropy: {file_info.get('entropy', 0.0)} ({'Packed' if pe_struct.get('is_packed') else 'Unpacked'})",
                f"Suspicious API Invocations: {len(api_stream)}",
                f"Extracted Indicators of Compromise: {ioc_count}",
                f"MITRE ATT&CK Techniques Mapped: {mitre_count}"
            ]
        }
