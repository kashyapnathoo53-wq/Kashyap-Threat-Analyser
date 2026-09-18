import os
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, JSONResponse
from pydantic import BaseModel

from static_analyzer import StaticAnalyzer
from yara_engine import YaraEngine
from behavioral_emulator import BehavioralEmulator
from ioc_extractor import IocExtractor
from mitre_mapper import MitreMapper
from threat_scorer import ThreatScorer
from reporter import Reporter
from samples_generator import get_preset_samples, get_preset_sample_by_id
from host_scanner import HostScanner

app = FastAPI(
    title="Kashyap Threat Analyser - Automated Malware Static & Behavioral Analysis Platform",
    description="Full Threat Scoring, IOC Extraction, MITRE ATT&CK Mapping, YARA Engine & Reporting",
    version="2.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analytical core engines
static_analyzer = StaticAnalyzer()
yara_engine = YaraEngine()
behavioral_emulator = BehavioralEmulator()
ioc_extractor = IocExtractor()
mitre_mapper = MitreMapper()
threat_scorer = ThreatScorer()
reporter = Reporter()
host_scanner = HostScanner()

# Global memory storage for analyzed reports
analysis_store: Dict[str, Any] = {}
latest_host_assessment: Dict[str, Any] = {}

class CustomYaraRequest(BaseModel):
    name: str
    category: str
    strings: List[str]
    condition: str

class PresetAnalyzeRequest(BaseModel):
    sample_id: str

@app.get("/")
def root():
    return {"status": "online", "platform": "Kashyap Threat Analyser v2.0"}

@app.get("/api/health")
def health():
    return {"status": "ok", "engines": ["static", "yara", "behavioral", "ioc", "mitre", "scorer", "reporter", "host_scanner"]}

@app.get("/api/system/auto-assess")
def get_system_auto_assess():
    global latest_host_assessment
    result = host_scanner.auto_assess_system()
    latest_host_assessment = result
    return result

@app.get("/api/system/quick-status")
def get_system_quick_status():
    global latest_host_assessment
    if not latest_host_assessment:
        latest_host_assessment = host_scanner.auto_assess_system()
    return {
        "status": latest_host_assessment.get("status", "HEALTHY / PROTECTED"),
        "health_score": latest_host_assessment.get("health_score", 100),
        "status_color": latest_host_assessment.get("status_color", "#22c55e"),
        "alert_level": latest_host_assessment.get("alert_level", "INFO"),
        "suspicious_processes": latest_host_assessment.get("summary", {}).get("suspicious_processes", 0),
        "vulnerabilities": latest_host_assessment.get("summary", {}).get("known_vulnerabilities_detected", 0)
    }

@app.get("/api/samples/presets")
def list_presets():
    return get_preset_samples()

def run_full_analysis(filename: str, content: bytes) -> Dict[str, Any]:
    file_info = {"filename": filename}
    
    # 1. Static Analysis
    static_res = static_analyzer.analyze(content, filename)
    
    # 2. YARA Rule Scan
    yara_res = yara_engine.scan(content)
    
    # 3. Behavioral Sandbox Emulation
    behavioral_res = behavioral_emulator.emulate_execution(content, file_info, static_res)
    
    # 4. IOC Extraction
    ioc_res = ioc_extractor.extract(content, static_res, behavioral_res)
    
    # 5. MITRE ATT&CK Mapping
    mitre_res = mitre_mapper.map_analysis(static_res, yara_res, behavioral_res, ioc_res)
    
    # 6. Threat Risk Scoring
    threat_res = threat_scorer.calculate_score(static_res, yara_res, behavioral_res, ioc_res, mitre_res)

    report_id = static_res["hashes"]["sha256"]

    result = {
        "report_id": report_id,
        "sample_name": filename,
        "timestamp": "2026-09-18T16:00:00Z",
        "static_analysis": static_res,
        "yara_scan": yara_res,
        "behavioral_analysis": behavioral_res,
        "ioc_extraction": ioc_res,
        "mitre_mapping": mitre_res,
        "threat_scoring": threat_res
    }

    # Store report in memory store
    analysis_store[report_id] = result
    return result

@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return run_full_analysis(file.filename, content)

@app.post("/api/analyze/preset")
def analyze_preset(req: PresetAnalyzeRequest):
    preset = get_preset_sample_by_id(req.sample_id)
    return run_full_analysis(preset["name"], preset["content_bytes"])

@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    if report_id not in analysis_store:
        raise HTTPException(status_code=404, detail="Report ID not found.")
    return analysis_store[report_id]

@app.get("/api/yara/rules")
def get_yara_rules():
    return yara_engine.get_rules()

@app.post("/api/yara/rules")
def add_yara_rule(req: CustomYaraRequest):
    rule = yara_engine.add_custom_rule(req.name, req.category, req.strings, req.condition)
    return {"message": "YARA rule compiled and registered", "rule": rule}

@app.get("/api/reports/{report_id}/export/{format_type}")
def export_report(report_id: str, format_type: str):
    if report_id not in analysis_store:
        # Fallback to default preset if sample not found
        preset = get_preset_sample_by_id("sample_wannacry")
        res = run_full_analysis(preset["name"], preset["content_bytes"])
    else:
        res = analysis_store[report_id]

    sample_name = res["sample_name"]
    s_res = res["static_analysis"]
    t_res = res["threat_scoring"]
    y_res = res["yara_scan"]
    b_res = res["behavioral_analysis"]
    i_res = res["ioc_extraction"]
    m_res = res["mitre_mapping"]

    if format_type == "stix":
        stix_bundle = reporter.generate_stix_21(sample_name, s_res, t_res, i_res, m_res)
        return JSONResponse(content=stix_bundle)
    elif format_type == "misp":
        misp_data = reporter.generate_misp(sample_name, s_res, i_res)
        return JSONResponse(content=misp_data)
    elif format_type == "markdown":
        md = reporter.generate_markdown(sample_name, s_res, t_res, y_res, b_res, i_res, m_res)
        return Response(content=md, media_type="text/markdown")
    elif format_type == "html":
        html = reporter.generate_html(sample_name, s_res, t_res, y_res, b_res, i_res, m_res)
        return HTMLResponse(content=html)
    else:
        raise HTTPException(status_code=400, detail="Invalid export format. Supported: stix, misp, markdown, html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
