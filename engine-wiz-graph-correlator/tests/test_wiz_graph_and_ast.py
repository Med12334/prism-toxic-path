from prism_graph.ast_reachability import VulnerableSymbol, verify_cve_reachability
from prism_graph.graph_correlator import WizCloudWorkloadContext, WizSecurityGraphCorrelator
from prism_graph.stride_threat_modeler import ArchitectureFeatureSpec, generate_automated_threat_model


def test_ast_reachability_distinguishes_called_vs_unused_vulnerable_dependency() -> None:
    vuln = VulnerableSymbol(
        cve_id="CVE-2026-4401",
        package_name="pyyaml",
        dangerous_function="unsafe_load",
        cvss_base=9.8,
    )

    exploitable_service_code = '''
import pyyaml

def helper_parse(raw_text: str):
    return pyyaml.unsafe_load(raw_text)

def api_ingest_manifest(request_body: str):
    return helper_parse(request_body)
'''
    reachable_res = verify_cve_reachability(exploitable_service_code, vuln)
    assert reachable_res.imported_in_code is True
    assert reachable_res.reachable_from_entrypoint is True
    assert reachable_res.call_chain == ["api_ingest_manifest", "helper_parse", "pyyaml.unsafe_load"]
    assert reachable_res.effective_priority == "P0_EXPLOITABLE_REACHABLE"

    dead_import_code = '''
import pyyaml

def unused_legacy_loader(data: str):
    return pyyaml.unsafe_load(data)

def api_healthcheck():
    return {"status": "ok"}
'''
    unreachable_res = verify_cve_reachability(dead_import_code, vuln)
    assert unreachable_res.imported_in_code is True
    assert unreachable_res.reachable_from_entrypoint is False
    assert unreachable_res.effective_priority == "P4_SUPPRESSED_UNREACHABLE_CODE"


def test_wiz_security_graph_correlator_blocks_toxic_combination_and_ignores_noise() -> None:
    correlator = WizSecurityGraphCorrelator()
    exposed_prod_pod = WizCloudWorkloadContext(
        workload_id="eks-prod-checkout-api",
        publicly_exposed_ingress=True,
        container_runs_as_root=True,
        has_cleartext_cloud_secret=True,
        iam_role_admin_permissions=True,
        production_data_store_connected=True,
    )

    # Case 1: High CVE + AST Reachable + Wiz Internet Ingress + IAM Admin = BLOCK
    toxic = correlator.evaluate_toxic_combination(
        wiz_ctx=exposed_prod_pod,
        cve_id="CVE-2026-4401",
        cvss_base=9.8,
        ast_reachable=True,
        call_chain=["api_ingest_manifest", "helper_parse", "pyyaml.unsafe_load"],
    )
    assert toxic.is_toxic_breach_path is True
    assert toxic.toxic_score >= 95.0
    assert toxic.release_gate_action == "BLOCK_RELEASE_CRITICAL_TOXIC_PATH"

    # Case 2: Same Pod, Same CVSS 9.8, but AST proves vulnerable function is never called = ALLOW
    non_toxic = correlator.evaluate_toxic_combination(
        wiz_ctx=exposed_prod_pod,
        cve_id="CVE-2026-4401",
        cvss_base=9.8,
        ast_reachable=False,
        call_chain=[],
    )
    assert non_toxic.is_toxic_breach_path is False
    assert non_toxic.release_gate_action == "ALLOW_WITH_BACKLOG_TICKET"


def test_automated_stride_and_ai_threat_model_generation() -> None:
    spec = ArchitectureFeatureSpec(
        feature_name="Autonomous AI Billing Webhook Service",
        exposes_public_webhook=True,
        uses_ai_coding_or_llm_agent=True,
        processes_customer_pii_or_secrets=True,
        executes_multi_tenant_containers=True,
    )
    model = generate_automated_threat_model(spec)
    assert model["threat_count"] == 4
    assert model["design_review_status"] == "APPROVED_WITH_MANDATORY_GUARDRAILS"
