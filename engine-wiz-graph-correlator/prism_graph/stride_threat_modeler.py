from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ArchitectureFeatureSpec:
    feature_name: str
    exposes_public_webhook: bool
    uses_ai_coding_or_llm_agent: bool
    processes_customer_pii_or_secrets: bool
    executes_multi_tenant_containers: bool


def generate_automated_threat_model(spec: ArchitectureFeatureSpec) -> Dict[str, object]:
    """
    Automates secure design reviews & threat modeling (STRIDE + AI Agent Threats)
    for new product features before code reaches production.
    """
    threats: List[Dict[str, str]] = []
    controls: List[str] = []

    if spec.exposes_public_webhook:
        threats.append({
            "category": "Spoofing & Tampering",
            "threat": "Unauthenticated webhook replay or SSRF payload injection",
        })
        controls.append("Enforce HMAC-SHA256 webhook signature verification + strict egress allowlist")

    if spec.uses_ai_coding_or_llm_agent:
        threats.append({
            "category": "AI Agent Prompt Injection & Slopsquatting",
            "threat": "Indirect prompt injection inducing rogue MCP tool execution or hallucinated package install",
        })
        controls.append("Route all AI agent diffs and MCP calls through Prism AI Guardrail Sandbox + lockfile provenance check")

    if spec.processes_customer_pii_or_secrets:
        threats.append({
            "category": "Information Disclosure",
            "threat": "PII or cloud credentials leaked into logs, telemetry, or AI model context windows",
        })
        controls.append("Enforce pre-commit entropy secret scanning + zero-retention LLM redaction proxy")

    if spec.executes_multi_tenant_containers:
        threats.append({
            "category": "Elevation of Privilege",
            "threat": "Container escape via root UID or writable hostPath volume mount",
        })
        controls.append("Enforce Wiz container policy: runAsNonRoot=true, readOnlyRootFilesystem=true, drop=['ALL']")

    return {
        "feature_name": spec.feature_name,
        "threat_count": len(threats),
        "identified_threats": threats,
        "mandatory_pre_prod_controls": controls,
        "design_review_status": "APPROVED_WITH_MANDATORY_GUARDRAILS" if controls else "LOW_RISK_AUTO_APPROVED",
    }
