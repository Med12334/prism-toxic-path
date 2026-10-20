from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class WizCloudWorkloadContext:
    """Represents runtime & posture context fetched from the Wiz Security Graph API."""
    workload_id: str
    publicly_exposed_ingress: bool
    container_runs_as_root: bool
    has_cleartext_cloud_secret: bool
    iam_role_admin_permissions: bool
    production_data_store_connected: bool


@dataclass(frozen=True)
class ToxicCombinationVerdict:
    workload_id: str
    cve_id: str
    toxic_score: float
    is_toxic_breach_path: bool
    release_gate_action: str
    attack_path_Chain: List[str] = field(default_factory=list)
    wiz_gap_enrichment_note: str = ""


class WizSecurityGraphCorrelator:
    """
    Correlates Wiz Cloud Graph posture signals (exposure, privileges, lateral movement secrets,
    and crown-jewel data access) with AST code reachability to eliminate alert fatigue.
    """

    def evaluate_toxic_combination(
        self,
        wiz_ctx: WizCloudWorkloadContext,
        cve_id: str,
        cvss_base: float,
        ast_reachable: bool,
        call_chain: List[str],
    ) -> ToxicCombinationVerdict:
        chain: List[str] = []
        score = cvss_base * 4.0  # Base scale out of 40

        if not ast_reachable:
            # Even a CVSS 9.8 is downgraded if the vulnerable function is never called
            return ToxicCombinationVerdict(
                workload_id=wiz_ctx.workload_id,
                cve_id=cve_id,
                toxic_score=round(cvss_base * 1.5, 2),
                is_toxic_breach_path=False,
                release_gate_action="ALLOW_WITH_BACKLOG_TICKET",
                attack_path_Chain=["UNREACHABLE_DEAD_DEPENDENCY_FUNCTION"],
                wiz_gap_enrichment_note="Downgraded via Prism AST Call-Graph Analyzer (function not reachable from any entrypoint).",
            )

        chain.append(f"AST_REACHABLE({ ' -> '.join(call_chain) })")
        score += 20.0

        if wiz_ctx.publicly_exposed_ingress:
            chain.append("WIZ_INTERNET_EXPOSED_INGRESS(0.0.0.0/0)")
            score += 15.0
        if wiz_ctx.container_runs_as_root:
            chain.append("WIZ_CONTAINER_PRIVILEGED_ROOT(UID=0)")
            score += 10.0
        if wiz_ctx.has_cleartext_cloud_secret or wiz_ctx.iam_role_admin_permissions:
            chain.append("WIZ_LATERAL_MOVEMENT_IAM_ADMIN_KEY")
            score += 10.0
        if wiz_ctx.production_data_store_connected:
            chain.append("WIZ_CROWN_JEWEL_PROD_DB_ACCESS")
            score += 5.0

        final_score = min(100.0, round(score, 2))
        is_toxic = (
            ast_reachable
            and wiz_ctx.publicly_exposed_ingress
            and (wiz_ctx.iam_role_admin_permissions or wiz_ctx.has_cleartext_cloud_secret or wiz_ctx.production_data_store_connected)
        )

        return ToxicCombinationVerdict(
            workload_id=wiz_ctx.workload_id,
            cve_id=cve_id,
            toxic_score=final_score,
            is_toxic_breach_path=is_toxic,
            release_gate_action="BLOCK_RELEASE_CRITICAL_TOXIC_PATH" if is_toxic else "WARN_REQUIRES_APPSEC_REVIEW",
            attack_path_Chain=chain,
            wiz_gap_enrichment_note="Confirmed exploitable via AST call graph + Wiz Cloud Graph correlation.",
        )
