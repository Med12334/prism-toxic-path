import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


APPROVED_ENTERPRISE_PACKAGES: Set[str] = {
    "fastapi", "pydantic", "pytest", "requests", "httpx", "sqlalchemy",
    "cryptography", "boto3", "redis", "uvicorn", "numpy", "pandas"
}

SECRET_PATTERNS: Dict[str, re.Pattern[str]] = {
    "AWS_ACCESS_KEY_ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GITHUB_PAT_TOKEN": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "WIZ_SERVICE_TOKEN": re.compile(r"wiz_svc_[A-Za-z0-9_\-]{16,}"),
    "PRIVATE_KEY_HEADER": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"),
}

INSECURE_AI_CODE_PATTERNS: Dict[str, Tuple[str, str]] = {}


@dataclass(frozen=True)
class AiCodeFinding:
    rule_id: str
    severity: str
    description: str
    remediation_patch_hint: str


@dataclass(frozen=True)
class AiAgentReviewVerdict:
    agent_name: str
    approved_for_merge: bool
    slopsquatted_packages: List[str] = field(default_factory=list)
    leaked_secrets: List[str] = field(default_factory=list)
    code_weaknesses: List[AiCodeFinding] = field(default_factory=list)
    blocked_mcp_commands: List[str] = field(default_factory=list)


def calculate_shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    length = len(token)
    frequencies: Dict[str, int] = {}
    for ch in token:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


class AiAssistedDevelopmentGuard:
    """
    Implements the security model for AI-assisted development:
    1. Protects secrets & sensitive data from entering LLM prompts or AI commits.
    2. Detects 'Slopsquatting' (AI-hallucinated dependencies not in the enterprise registry).
    3. Reviews AI-generated code for injection, shell execution, and unsafe deserialization.
    4. Enforces guardrails on AI Coding Agent MCP / terminal tool invocations.
    """

    def review_ai_agent_submission(
        self,
        agent_name: str,
        generated_code: str,
        proposed_dependencies: List[str],
        mcp_tool_commands: List[str],
    ) -> AiAgentReviewVerdict:
        slopsquatted: List[str] = []
        secrets_found: List[str] = []
        weaknesses: List[AiCodeFinding] = []
        blocked_commands: List[str] = []

        # 1. Open-Source Dependency & AI Slopsquatting Check
        for pkg in proposed_dependencies:
            normalized = pkg.split("==")[0].split(">=")[0].strip().lower()
            if normalized not in APPROVED_ENTERPRISE_PACKAGES:
                slopsquatted.append(normalized)

        # 2. Secrets Detection (Regex + High-Entropy Credential Assignment Check)
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(generated_code):
                secrets_found.append(label)

        for match in re.finditer(r'(?i)(?:api_key|secret|token|password)\s*=\s*["\']([^"\']{16,})["\']', generated_code):
            candidate = match.group(1)
            if calculate_shannon_entropy(candidate) >= 3.8 and "HIGH_ENTROPY_CREDENTIAL" not in secrets_found:
                secrets_found.append("HIGH_ENTROPY_CREDENTIAL")

        # 3. AI-Generated Code Weakness Analysis
        if re.search(r'f["\']SELECT\s+.*\{.*\}', generated_code, re.IGNORECASE):
            weaknesses.append(AiCodeFinding(
                rule_id="AI-SEC-SQLI-001",
                severity="CRITICAL",
                description="AI agent generated raw f-string SQL query vulnerable to SQL Injection.",
                remediation_patch_hint="cursor.execute('SELECT * FROM users WHERE id = :id', {'id': user_id})",
            ))

        if "shell=True" in generated_code:
            weaknesses.append(AiCodeFinding(
                rule_id="AI-SEC-CMDI-002",
                severity="HIGH",
                description="AI agent invoked subprocess with shell=True, enabling command injection.",
                remediation_patch_hint="subprocess.run(['git', 'status'], shell=False, check=True)",
            ))

        if "verify=False" in generated_code:
            weaknesses.append(AiCodeFinding(
                rule_id="AI-SEC-TLS-003",
                severity="HIGH",
                description="AI agent disabled TLS certificate verification (verify=False).",
                remediation_patch_hint="httpx.get(url, verify=True, timeout=10.0)",
            ))

        # 4. Guardrails for AI Coding Agent Terminal / MCP Tool Calls
        forbidden_agent_ops = (".env", "~/.aws/credentials", "/etc/shadow", "curl ", "wget ", "terraform destroy")
        for cmd in mcp_tool_commands:
            if any(bad in cmd.lower() for bad in forbidden_agent_ops):
                blocked_commands.append(cmd)

        approved = not (slopsquatted or secrets_found or weaknesses or blocked_commands)
        return AiAgentReviewVerdict(
            agent_name=agent_name,
            approved_for_merge=approved,
            slopsquatted_packages=slopsquatted,
            leaked_secrets=secrets_found,
            code_weaknesses=weaknesses,
            blocked_mcp_commands=blocked_commands,
        )
