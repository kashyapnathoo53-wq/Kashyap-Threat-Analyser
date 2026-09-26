import uuid
from typing import Dict, List, Any, Optional

from agent.models.candidate import SuspiciousCandidate
from agent.models.snapshot import SecuritySnapshot
from agent.models.diff import SecurityDiffResult
from agent.models.metrics import EvidenceFactor, DualThreatMetrics


def evaluate_dual_metrics(
    candidate: SuspiciousCandidate,
    report: Optional[Dict[str, Any]] = None,
    snapshot: Optional[SecuritySnapshot] = None,
    diff: Optional[SecurityDiffResult] = None
) -> DualThreatMetrics:
    """
    Evaluates independent Risk Severity (potential harm) and Evidentiary Confidence
    (certainty of proof) metrics, mapping into an operational action quadrant.
    """
    metric_id = f"metric_{uuid.uuid4().hex[:8]}"
    factors: List[EvidenceFactor] = []

    # -------------------------------------------------------------
    # 1. HEURISTIC & HOST CONTEXT FACTORS
    # -------------------------------------------------------------
    if candidate.heuristics_matched:
        factors.append(EvidenceFactor(
            factor_name=f"Host Heuristic Anomaly ({len(candidate.heuristics_matched)} rule hits)",
            factor_type="HEURISTIC_ANOMALY",
            weight=1.0,
            risk_contribution=min(30, int(candidate.priority_score * 0.3)),
            confidence_contribution=15,
            description=f"Initial discovery flagged: {', '.join(candidate.heuristics_matched)}",
            evidence_data={"heuristics": candidate.heuristics_matched, "priority": candidate.priority_score}
        ))

    cand_path = (candidate.target_path or candidate.metadata.get("path", "")).lower()
    if any(loc in cand_path for loc in ["\\temp\\", "\\appdata\\local\\temp", "\\downloads\\"]):
        factors.append(EvidenceFactor(
            factor_name="Untrusted Execution Directory",
            factor_type="HOST_CONTEXT",
            weight=1.0,
            risk_contribution=25,
            confidence_contribution=15,
            description="Process or payload executed from volatile user temporary or download directory.",
            evidence_data={"path": candidate.target_path}
        ))

    # -------------------------------------------------------------
    # 2. STATIC SIGNATURE FACTORS
    # -------------------------------------------------------------
    if report:
        yara_res = report.get("yara_scan", {})
        matches = yara_res.get("matches", [])
        if matches:
            rule_names = [m.get("rule", "unknown") for m in matches]
            factors.append(EvidenceFactor(
                factor_name=f"YARA Signature Matches ({len(matches)} rule hits)",
                factor_type="DETERMINISTIC_SIGNATURE",
                weight=1.5,
                risk_contribution=35,
                confidence_contribution=min(40, len(matches) * 20),
                description=f"Deterministic byte signatures matched: {', '.join(rule_names)}",
                evidence_data={"rules": rule_names}
            ))

        static_res = report.get("static_analysis", {})
        entropy_val = static_res.get("entropy", {}).get("value", 0.0)
        if entropy_val > 7.0:
            factors.append(EvidenceFactor(
                factor_name="Elevated Shannon Entropy (Packed / Obfuscated)",
                factor_type="HEURISTIC_ANOMALY",
                weight=1.0,
                risk_contribution=20,
                confidence_contribution=15,
                description=f"Calculated entropy {entropy_val:.2f}/8.0 indicates high probability of compression, encryption, or packing.",
                evidence_data={"entropy": entropy_val}
            ))

    # -------------------------------------------------------------
    # 3. BEHAVIORAL EXECUTION FACTORS
    # -------------------------------------------------------------
    if report:
        behavioral_res = report.get("behavioral_analysis", {})

        # API Call Stream (Injections)
        stream = behavioral_res.get("api_call_stream", [])
        injections = [c for c in stream if c.get("api") in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]]
        if injections:
            factors.append(EvidenceFactor(
                factor_name=f"Process Memory Injection Observed ({len(injections)} call hits)",
                factor_type="BEHAVIORAL_TELEMETRY",
                weight=1.8,
                risk_contribution=40,
                confidence_contribution=30,
                description="Process attempted inter-process memory allocation or remote thread creation.",
                evidence_data={"injection_calls": [c.get("api") for c in injections]}
            ))

        # Persistence Activity
        reg_acts = behavioral_res.get("registry_activity", [])
        if isinstance(reg_acts, list) and reg_acts:
            run_keys = [r for r in reg_acts if isinstance(r, dict) and "run" in str(r.get("key", "") or r.get("path", "")).lower()]
            if run_keys:
                factors.append(EvidenceFactor(
                    factor_name="Startup Persistence Registry Modification",
                    factor_type="BEHAVIORAL_TELEMETRY",
                    weight=1.5,
                    risk_contribution=30,
                    confidence_contribution=25,
                    description="Payload configured automated operating system startup keys.",
                    evidence_data={"keys": [r.get("key") or r.get("path") for r in run_keys]}
                ))

        # C2 Network Activity
        net_acts = behavioral_res.get("network_activity", [])
        if isinstance(net_acts, list) and net_acts:
            destinations = [n.get("destination") or n.get("domain") for n in net_acts if isinstance(n, dict)]
            factors.append(EvidenceFactor(
                factor_name=f"Outbound C2 Network Telemetry ({len(destinations)} destination(s))",
                factor_type="BEHAVIORAL_TELEMETRY",
                weight=1.5,
                risk_contribution=35,
                confidence_contribution=25,
                description=f"Established outbound telemetry or beaconing to remote endpoint(s): {', '.join(str(d) for d in destinations[:3])}",
                evidence_data={"destinations": destinations}
            ))

    # -------------------------------------------------------------
    # 4. DIFFERENTIAL SNAPSHOT CONFIRMATION
    # -------------------------------------------------------------
    if diff:
        new_procs = diff.process_changes.get("new_processes", [])
        if any(np.get("name") == candidate.name for np in new_procs if isinstance(np, dict)):
            factors.append(EvidenceFactor(
                factor_name="Dynamic Differential Appearance",
                factor_type="HOST_CONTEXT",
                weight=1.0,
                risk_contribution=15,
                confidence_contribution=15,
                description="Process was dynamically spawned between subsequent host snapshots.",
                evidence_data={"diff_id": diff.diff_id}
            ))

    # -------------------------------------------------------------
    # 5. METRIC AGGREGATION & SEPARATION
    # -------------------------------------------------------------
    raw_risk = sum(f.risk_contribution for f in factors)
    raw_conf = sum(f.confidence_contribution for f in factors)

    if report:
        threat_score = report.get("threat_scoring", {}).get("threat_score", 50)
        risk_score = min(100, max(15, int((raw_risk * 0.6) + (threat_score * 0.4))))
        confidence_score = min(98, max(25, raw_conf))
    else:
        # Without sandbox emulation, cap confidence at 50% max to protect from destructive false positives
        risk_score = min(100, max(10, candidate.priority_score))
        confidence_score = min(50, max(15, raw_conf))

    # Assign Risk Tier
    if risk_score >= 80:
        risk_tier = "CRITICAL"
    elif risk_score >= 60:
        risk_tier = "HIGH"
    elif risk_score >= 40:
        risk_tier = "MEDIUM"
    elif risk_score >= 20:
        risk_tier = "LOW"
    else:
        risk_tier = "INFORMATIONAL"

    # Assign Confidence Tier
    if confidence_score >= 80:
        confidence_tier = "CONFIRMED"
    elif confidence_score >= 60:
        confidence_tier = "HIGH_CONFIDENCE"
    elif confidence_score >= 35:
        confidence_tier = "MODERATE"
    else:
        confidence_tier = "SPECULATIVE"

    # Determine Action Quadrant
    if risk_score >= 75 and confidence_score >= 75:
        action_classification = "AUTOMATED_CONTAINMENT"
        rationale = (
            f"Both Risk ({risk_score}/100) and Evidentiary Confidence ({confidence_score}%) are critically high. "
            "Corroborating deterministic signatures and active behavioral proof justify immediate automated host containment."
        )
    elif risk_score >= 75 and confidence_score < 75:
        action_classification = "URGENT_ANALYST_REVIEW"
        rationale = (
            f"Risk is critical ({risk_score}/100) but Evidentiary Confidence is incomplete ({confidence_score}%). "
            "Automated destructive actions are withheld to avoid user disruption; immediate analyst inspection is recommended."
        )
    elif risk_score >= 40:
        action_classification = "SCHEDULED_INVESTIGATION"
        rationale = (
            f"Moderate risk severity ({risk_score}/100) with {confidence_tier.lower()} confidence ({confidence_score}%). "
            "Candidate is scheduled for routine forensic inspection."
        )
    else:
        action_classification = "OBSERVE_AND_LOG"
        rationale = (
            f"Low risk severity ({risk_score}/100) with {confidence_tier.lower()} confidence ({confidence_score}%). "
            "Artifact does not present an immediate threat; telemetry is recorded."
        )

    return DualThreatMetrics(
        metric_id=metric_id,
        candidate_id=candidate.candidate_id,
        candidate_name=candidate.name,
        risk_score=risk_score,
        confidence_score=confidence_score,
        risk_tier=risk_tier,
        confidence_tier=confidence_tier,
        action_classification=action_classification,
        factors=factors,
        rationale=rationale
    )
