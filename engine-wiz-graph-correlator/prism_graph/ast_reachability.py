import ast
from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass(frozen=True)
class VulnerableSymbol:
    cve_id: str
    package_name: str
    dangerous_function: str
    cvss_base: float


@dataclass(frozen=True)
class ReachabilityResult:
    cve_id: str
    package_name: str
    dangerous_function: str
    imported_in_code: bool
    reachable_from_entrypoint: bool
    call_chain: List[str]
    effective_priority: str


class CallGraphExtractor(ast.NodeVisitor):
    """
    Closes a critical gap that cloud scanners like Wiz do not cover natively:
    constructs an intra-module AST call graph from entrypoints (e.g., API handlers)
    down to third-party library sinks to prove whether a CVE is actually reachable.
    """

    def __init__(self) -> None:
        self.imports: Dict[str, str] = {}
        self.function_calls: Dict[str, Set[str]] = {}
        self.entrypoints: Set[str] = set()
        self._current_function: str = "<module>"
        self.function_calls[self._current_function] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound_name = alias.asname or alias.name
            self.imports[bound_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            bound_name = alias.asname or alias.name
            self.imports[bound_name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_function
        self._current_function = node.name
        self.function_calls.setdefault(node.name, set())

        # Treat route-decorated functions or `handle_*` / `api_*` as public entrypoints
        if node.decorator_list or node.name.startswith(("api_", "handle_", "route_", "webhook_")):
            self.entrypoints.add(node.name)

        self.generic_visit(node)
        self._current_function = prev

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._resolve_callee_name(node.func)
        if callee:
            self.function_calls.setdefault(self._current_function, set()).add(callee)
        self.generic_visit(node)

    def _resolve_callee_name(self, func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return self.imports.get(func_node.id, func_node.id)
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            base = self.imports.get(func_node.value.id, func_node.value.id)
            return f"{base}.{func_node.attr}"
        return ""


def verify_cve_reachability(source_code: str, vuln: VulnerableSymbol) -> ReachabilityResult:
    tree = ast.parse(source_code)
    extractor = CallGraphExtractor()
    extractor.visit(tree)

    target_fqn = f"{vuln.package_name}.{vuln.dangerous_function}"
    imported = any(
        mapped == vuln.package_name or mapped == target_fqn or mapped.startswith(f"{vuln.package_name}.")
        for mapped in extractor.imports.values()
    )

    # BFS from all public entrypoints to see if target_fqn is reachable
    visited: Set[str] = set()
    queue: List[List[str]] = [[ep] for ep in sorted(extractor.entrypoints)]

    while queue:
        path = queue.pop(0)
        current = path[-1]
        if current == target_fqn:
            return ReachabilityResult(
                cve_id=vuln.cve_id,
                package_name=vuln.package_name,
                dangerous_function=vuln.dangerous_function,
                imported_in_code=True,
                reachable_from_entrypoint=True,
                call_chain=path,
                effective_priority="P0_EXPLOITABLE_REACHABLE" if vuln.cvss_base >= 7.0 else "P1_REACHABLE",
            )
        if current not in visited:
            visited.add(current)
            for neighbor in sorted(extractor.function_calls.get(current, set())):
                queue.append(path + [neighbor])

    return ReachabilityResult(
        cve_id=vuln.cve_id,
        package_name=vuln.package_name,
        dangerous_function=vuln.dangerous_function,
        imported_in_code=imported,
        reachable_from_entrypoint=False,
        call_chain=[],
        effective_priority="P4_SUPPRESSED_UNREACHABLE_CODE",
    )
