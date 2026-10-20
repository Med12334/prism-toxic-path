from ai_guard.agent_guardrail import AiAssistedDevelopmentGuard


def test_ai_guard_catches_slopsquatting_secrets_sqli_and_rogue_mcp_commands() -> None:
    guard = AiAssistedDevelopmentGuard()

    risky_ai_code = '''
import subprocess

WIZ_TOKEN = "wiz_svc_99aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"

def fetch_user(cursor, user_input: str):
    query = f"SELECT * FROM accounts WHERE username = '{user_input}'"
    subprocess.run(f"echo {user_input}", shell=True)
    return cursor.execute(query)
'''
    verdict = guard.review_ai_agent_submission(
        agent_name="cursor-agent-v2",
        generated_code=risky_ai_code,
        proposed_dependencies=["fastapi==0.115.0", "python-aws-magic-helper==1.0.0"],
        mcp_tool_commands=["pytest -q", "cat ~/.aws/credentials"],
    )

    assert verdict.approved_for_merge is False
    assert "python-aws-magic-helper" in verdict.slopsquatted_packages
    assert "WIZ_SERVICE_TOKEN" in verdict.leaked_secrets
    assert len(verdict.code_weaknesses) == 2
    assert verdict.blocked_mcp_commands == ["cat ~/.aws/credentials"]


def test_ai_guard_approves_clean_parameterized_ai_code() -> None:
    guard = AiAssistedDevelopmentGuard()

    clean_ai_code = '''
def fetch_user_safe(cursor, user_id: int):
    return cursor.execute("SELECT id, email FROM accounts WHERE id = :uid", {"uid": user_id})
'''
    verdict = guard.review_ai_agent_submission(
        agent_name="copilot-workspace",
        generated_code=clean_ai_code,
        proposed_dependencies=["fastapi==0.115.0", "pydantic==2.9.2"],
        mcp_tool_commands=["pytest -v"],
    )

    assert verdict.approved_for_merge is True
    assert verdict.slopsquatted_packages == []
    assert verdict.leaked_secrets == []
    assert verdict.code_weaknesses == []
    assert verdict.blocked_mcp_commands == []
