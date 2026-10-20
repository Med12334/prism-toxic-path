# Prism-Toxic-Path (`io.prism.appsec`)
### Code-to-Cloud Wiz Security Graph Correlator, Function-Level AST Reachability Analyzer, AI Coding Agent Guardrail & Zero-Noise Developer PR Auto-Fix Engine

`prism-toxic-path` is an end-to-end Application Security (AppSec) platform built around **Wiz as the core cloud & posture platform**, while closing the critical application-layer gaps that cloud scanners do not cover natively.

---

## Why `prism-toxic-path` Exists

1. **Wiz Security Graph + Code Reachability Correlation (`engine-wiz-graph-correlator/`):**
   - Ingests runtime and posture signals from the Wiz Security Graph (public ingress `0.0.0.0/0`, privileged root containers, cleartext cloud keys, IAM Admin roles, and production database connections).
   - **Closes Wiz's Static Call-Graph Gap:** Uses Python's native `ast` module (`ast_reachability.py`) to build a function-level call graph from public API entrypoints down to third-party library sinks—proving whether a CVE is actually reachable in execution or dead code that should be auto-suppressed.
   - **Automated STRIDE-LM Threat Modeling (`stride_threat_modeler.py`):** Generates pre-production threat models and mandatory security controls for new product features during design review.

2. **Security Model for AI-Assisted Development (`guard-ai-coding-agent/`):**
   - **Slopsquatting Protection:** Blocks AI coding agents (Cursor, Copilot, Claude Code) from introducing hallucinated or unverified open-source packages.
   - **Shannon Entropy + Pattern Secret Guard:** Prevents credentials, Wiz service tokens, AWS keys, and private keys from being committed by AI agents or leaked into LLM prompts.
   - **AI Code Review & MCP Tool Firewall:** Inspects AI-generated diffs for raw f-string SQL injection, `shell=True` command execution, disabled TLS verification, and rogue MCP terminal commands (`cat ~/.aws/credentials`).

3. **Automated Container & IaC Release Gates (`scanner-iac-container-gate/`):**
   - Written in **Go 1.22** to enforce sub-millisecond CI/CD release gates across Dockerfiles (unpinned tags, root UID), Kubernetes manifests (`privileged`, writable rootfs), and Terraform plans (public S3 ACLs, `0.0.0.0/0` ingress).

4. **Zero-Noise Developer PR Delivery (`developer-pr-sarif-bot/`):**
   - Written in **Node.js 20 ESM** to deliver prioritized, confirmed-exploitable Toxic Paths directly inside GitHub Pull Requests using **SARIF v2.1.0** and one-click GitHub `suggestion` auto-fix blocks.
