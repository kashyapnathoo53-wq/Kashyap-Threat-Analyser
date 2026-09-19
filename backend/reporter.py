import json
import time
from typing import Dict, List, Any

class Reporter:
    def __init__(self):
        pass

    def generate_stix_21(self, sample_name: str, static_res: Dict[str, Any], threat_res: Dict[str, Any], ioc_res: Dict[str, Any], mitre_res: Dict[str, Any]) -> Dict[str, Any]:
        hashes = static_res.get("hashes", {})
        sha256 = hashes.get("sha256", "")
        
        objects = [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": f"malware--{sha256[:36]}",
                "created": "2026-09-18T16:00:00.000Z",
                "modified": "2026-09-18T16:00:00.000Z",
                "name": sample_name,
                "is_family": False,
                "malware_types": ["ransomware" if "CRITICAL" in threat_res.get("severity", "") else "trojan"],
                "description": f"Automated Sandbox Scan Report. Threat Score: {threat_res.get('threat_score')}/100. Verdict: {threat_res.get('verdict')}"
            }
        ]

        # Add IOC indicators
        for ioc in ioc_res.get("iocs", []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hash(ioc['value']) & 0xffffffffffffffff:016x}",
                "pattern": f"[{ioc['type'].lower().replace(' ', '-')} = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": "2026-09-18T16:00:00.000Z",
                "indicator_types": [ioc["category"].lower().replace(" ", "-")]
            })

        return {
            "type": "bundle",
            "id": f"bundle--{sha256[:36]}",
            "spec_version": "2.1",
            "objects": objects
        }

    def generate_misp(self, sample_name: str, static_res: Dict[str, Any], ioc_res: Dict[str, Any]) -> Dict[str, Any]:
        hashes = static_res.get("hashes", {})
        attributes = []
        for ioc in ioc_res.get("iocs", []):
            attributes.append({
                "type": ioc["type"],
                "value": ioc["value"],
                "category": ioc["category"],
                "comment": "Automated Sandbox Extraction"
            })
        return {
            "Event": {
                "info": f"Malware Analysis: {sample_name}",
                "date": "2026-09-18",
                "threat_level_id": "1",
                "Attribute": attributes
            }
        }

    def generate_markdown(self, sample_name: str, static_res: Dict[str, Any], threat_res: Dict[str, Any], yara_res: Dict[str, Any], behavioral_res: Dict[str, Any], ioc_res: Dict[str, Any], mitre_res: Dict[str, Any]) -> str:
        hashes = static_res.get("hashes", {})
        f_info = static_res.get("file_info", {})
        
        md = f"""# Pasha - Malware Analysis Report
**Sample Target:** `{sample_name}`
**Analysis Date:** 2026-09-18
**Threat Score:** {threat_res.get('threat_score')}/100 (**{threat_res.get('verdict')}**)

---

## 1. Executive Summary
- **File Type:** {f_info.get('type')}
- **Architecture:** {f_info.get('architecture')}
- **Entropy:** {f_info.get('entropy')} ({'Packed' if static_res.get('pe_structure', {}).get('is_packed') else 'Unpacked'})
- **MD5:** `{hashes.get('md5')}`
- **SHA256:** `{hashes.get('sha256')}`
- **YARA Matches:** {len(yara_res.get('matches', []))}
- **Extracted IOCs:** {ioc_res.get('total_extracted')}

---

## 2. Threat Scoring Breakdown
- **Static Score:** {threat_res.get('score_breakdown', {}).get('static_score')}/25
- **YARA Signature Score:** {threat_res.get('score_breakdown', {}).get('yara_score')}/25
- **Behavioral Sandbox Score:** {threat_res.get('score_breakdown', {}).get('behavioral_score')}/30
- **IOC Density Score:** {threat_res.get('score_breakdown', {}).get('ioc_score')}/10
- **MITRE ATT&CK Score:** {threat_res.get('score_breakdown', {}).get('mitre_score')}/10

---

## 3. YARA Signature Detections
"""
        for y in yara_res.get("matches", []):
            md += f"- **{y['rule_name']}** [{y['severity']}] - {y['description']}\n"
            md += f"  - Matched Strings: `{', '.join(y['matched_strings'])}` \n"

        md += "\n---\n\n## 4. Extracted Indicators of Compromise (IOCs)\n"
        md += "| Type | Value | Category | Risk |\n| --- | --- | --- | --- |\n"
        for ioc in ioc_res.get("iocs", []):
            md += f"| {ioc['type']} | `{ioc['value']}` | {ioc['category']} | {ioc['threat_intel'].get('risk', 'MEDIUM')} |\n"

        md += "\n---\n\n## 5. MITRE ATT&CK TTP Mapping\n"
        md += "| Tactic | Technique ID | Technique Name | Evidence |\n| --- | --- | --- | --- |\n"
        for tech in mitre_res.get("mapped_techniques", []):
            md += f"| {tech['tactic_name']} | `{tech['technique_id']}` | {tech['technique_name']} | {tech['evidence']} |\n"

        return md

    def generate_html(self, sample_name: str, static_res: Dict[str, Any], threat_res: Dict[str, Any], yara_res: Dict[str, Any], behavioral_res: Dict[str, Any], ioc_res: Dict[str, Any], mitre_res: Dict[str, Any]) -> str:
        hashes = static_res.get("hashes", {})
        f_info = static_res.get("file_info", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pasha - {sample_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #080502; color: #f8fafc; padding: 30px; line-height: 1.6; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #7c2d12; padding-bottom: 20px; margin-bottom: 30px; }}
        .badge {{ background: {threat_res.get('color')}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 1.1em; }}
        .card {{ background: #140c07; border-radius: 12px; padding: 20px; margin-bottom: 25px; border: 1px solid #7c2d12; }}
        h1 {{ color: #ffffff; margin: 0; }}
        h2 {{ color: #f97316; margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #431407; }}
        th {{ background: #0f0804; color: #fdba74; }}
        code {{ background: #1c0d06; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #fb923c; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Pasha - Analysis Report</h1>
            <p style="color: #fdba74">Target Sample: <strong>{sample_name}</strong> | Generated: 2026-09-18</p>
        </div>
        <div class="badge">{threat_res.get('threat_score')}/100 - {threat_res.get('verdict')}</div>
    </div>

    <div class="card">
        <h2>Executive File Metadata</h2>
        <p><strong>File Type:</strong> {f_info.get('type')} ({f_info.get('architecture')})</p>
        <p><strong>Entropy:</strong> {f_info.get('entropy')} | <strong>MD5:</strong> <code>{hashes.get('md5')}</code></p>
        <p><strong>SHA256:</strong> <code>{hashes.get('sha256')}</code></p>
    </div>

    <div class="card">
        <h2>YARA Signature Matches ({len(yara_res.get('matches', []))})</h2>
        <table>
            <tr><th>Rule Name</th><th>Severity</th><th>Description</th></tr>
            {"".join([f"<tr><td><code>{m['rule_name']}</code></td><td>{m['severity']}</td><td>{m['description']}</td></tr>" for m in yara_res.get('matches', [])])}
        </table>
    </div>

    <div class="card">
        <h2>Extracted Indicators of Compromise ({ioc_res.get('total_extracted')})</h2>
        <table>
            <tr><th>Type</th><th>Value</th><th>Category</th></tr>
            {"".join([f"<tr><td>{i['type']}</td><td><code>{i['value']}</code></td><td>{i['category']}</td></tr>" for i in ioc_res.get('iocs', [])])}
        </table>
    </div>

    <div class="card">
        <h2>MITRE ATT&CK TTP Mapping ({mitre_res.get('total_mapped_techniques')})</h2>
        <table>
            <tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Evidence</th></tr>
            {"".join([f"<tr><td>{t['tactic_name']}</td><td><code>{t['technique_id']}</code></td><td>{t['technique_name']}</td><td>{t['evidence']}</td></tr>" for t in mitre_res.get('mapped_techniques', [])])}
        </table>
    </div>
</body>
</html>"""
        return html
