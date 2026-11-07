"""Conservative SAST heuristics, not ASVS certification or proof of safety.

Local assignments are followed within lexical scopes; interprocedural analysis,
arbitrary validator implementations and object-level authorization are not proved.
Unknown validation helpers never suppress a finding. Mitigated phases describe
potential interruption AFTER applying all reported remediations, not live controls.
"""

import ast
import re

from cybermatch.models.secure_coding import (
    KillChainPhase, SecureCodingAuditResult, Severity,
    VulnerabilityCategory as Category, VulnerabilityFinding,
)


PENALTIES = {Severity.CRITICAL: .3, Severity.HIGH: .2,
             Severity.MEDIUM: .1, Severity.LOW: .05}
# ASVS 4.0.3 IDs. Guides include examples and their necessary security context.
RULES = {
    Category.SQLI: (Severity.CRITICAL, "V5.3.4", "Dynamic SQL passed to an execution sink.",
                   'Use bound values: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)). Allowlist dynamic identifiers.'),
    Category.XSS: (Severity.HIGH, "V5.3.3", "HTML escaping is bypassed or disabled.",
                  'Keep autoescaping enabled: return render(request, "page.html", {"value": value}); template: {{ value }}. Sanitize intentionally allowed HTML with a maintained allowlist sanitizer.'),
    Category.CSRF: (Severity.MEDIUM, "V4.2.2", "CSRF protection is explicitly disabled.",
                   'Remove @csrf_exempt; enable CsrfViewMiddleware and include {% csrf_token %} in state-changing forms.'),
    Category.SSRF: (Severity.HIGH, "V5.2.6", "Dynamic outbound URL requires destination validation review.",
                   'Map user choices to fixed endpoints: endpoints = {"status": "https://api.example.com/status"}; requests.get(endpoints[choice], timeout=5, allow_redirects=False). Enforce egress allowlists; reject private, loopback, link-local and metadata addresses in every resolved IPv4/IPv6 destination and redirect, preventing DNS rebinding.'),
    Category.IDOR_BOLA: (Severity.HIGH, "V4.2.1", "Request-controlled object lookup lacks visible owner scoping.",
                        'Scope lookup to the authenticated principal: User.objects.get(id=request.GET["id"], id__in=authorized_user_ids(request.user)). Derive permissions server-side and deny by default.'),
    Category.COMMAND_INJECTION: (Severity.CRITICAL, "V5.3.8", "Dynamic command passed to a shell.",
                                 'Avoid the shell: subprocess.run(["/usr/bin/tool", "--", value], shell=False, check=True). Allowlist commands and validate arguments.'),
}
PHASES = {category: (KillChainPhase.EXPLOITATION,) for category in Category}
PHASES[Category.IDOR_BOLA] = (KillChainPhase.ACTIONS_ON_OBJECTIVES,)
TEMPLATE_PATTERN = re.compile(r"\|\s*safe\b|{%\s*autoescape\s+(?:off|false)\b", re.IGNORECASE)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


class _Scanner(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.bindings = {}
        self.dynamic_names: set[str] = set()
        self.aliases = {}
        self.findings = {}

    def report(self, category, node):
        severity, requirement, description, guide = RULES[category]
        self.findings[(node.lineno, category)] = VulnerabilityFinding(
            category, severity, node.lineno, ast.get_source_segment(self.code, node) or "",
            description, guide, requirement)

    def resolve(self, node, seen=frozenset()):
        if isinstance(node, ast.Name) and node.id in self.bindings and node.id not in seen:
            return self.resolve(self.bindings[node.id], seen | {node.id})
        return node

    def dynamic(self, node):
        if isinstance(node, ast.Name) and node.id in self.dynamic_names:
            return True
        node = self.resolve(node)
        if isinstance(node, ast.Subscript):
            mapping = self.resolve(node.value)
            if not (isinstance(node.value, ast.Name) and node.value.id in self.dynamic_names):
                if isinstance(mapping, ast.Dict) and mapping.keys and all(
                        isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and isinstance(value, ast.Constant) and isinstance(value.value, str)
                        for key, value in zip(mapping.keys, mapping.values)):
                    return False
        return not (isinstance(node, ast.Constant) and isinstance(node.value, str))

    def bind(self, target, value):
        if isinstance(target, ast.Name):
            # Dictionaries retain their structure for fixed endpoint lookups.
            if self.dynamic(value) and not isinstance(self.resolve(value), ast.Dict):
                self.dynamic_names.add(target.id)
            self.bindings[target.id] = self.resolve(value)

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.bind(target, node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.bind(node.target, node.value)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            if self.dynamic(node.target) or self.dynamic(node.value):
                self.dynamic_names.add(node.target.id)
            else:
                self.bindings[node.target.id] = ast.Constant(
                    self.resolve(node.target).value + self.resolve(node.value).value)

    def visit_Constant(self, node):
        # Embedded Django/Jinja templates also occur in Python string literals.
        if isinstance(node.value, str) and ("{{" in node.value or "{%" in node.value):
            if TEMPLATE_PATTERN.search(node.value):
                self.report(Category.XSS, node)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        previous, aliases = self.bindings, self.aliases.copy()
        previous_dynamic = self.dynamic_names
        self.dynamic_names = previous_dynamic.copy()
        self.bindings = previous.copy()
        # A parameter shadows any same-named outer constant.
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.bindings.pop(arg.arg, None)
            self.dynamic_names.discard(arg.arg)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg is not None:
                self.bindings.pop(arg.arg, None)
                self.dynamic_names.discard(arg.arg)
        for statement in node.body:
            self.visit(statement)
        self.bindings, self.aliases = previous, aliases
        self.dynamic_names = previous_dynamic

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node):
        name = self.aliases.get(node.id, node.id)
        if name.split(".")[-1] == "csrf_exempt":
            self.report(Category.CSRF, node)

    def visit_Attribute(self, node):
        if node.attr == "csrf_exempt":
            self.report(Category.CSRF, node)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _name(node.func)
        root, _, tail = name.partition(".")
        name = self.aliases.get(root, root) + ("." + tail if tail else "")
        leaf = node.func.attr if isinstance(node.func, ast.Attribute) else name.split(".")[-1]
        keywords = {kw.arg: kw.value for kw in node.keywords}
        first = node.args[0] if node.args else keywords.get("url")
        if leaf in {"execute", "executemany", "executescript", "raw"}:
            query = node.args[0] if node.args else keywords.get("sql", keywords.get("query"))
            db_context = any(part in {"cursor", "conn", "connection", "db", "session", "models", "objects"}
                             for part in name.lower().split(".")[:-1])
            sql_context = query is not None and any(
                isinstance(part, ast.Constant) and isinstance(part.value, str)
                and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH)\b", part.value, re.I)
                for part in ast.walk(self.resolve(query)))
            if query is not None and self.dynamic(query) and (
                    db_context or "sql" in keywords or "query" in keywords or sql_context):
                self.report(Category.SQLI, node)
        if leaf in {"mark_safe", "Markup"} or any(
                key == "autoescape" and isinstance(value, ast.Constant) and value.value is False
                for key, value in keywords.items()):
            self.report(Category.XSS, node)
        receiver = self.resolve(node.func.value) if isinstance(node.func, ast.Attribute) else None
        session_call = isinstance(receiver, ast.Call) and _name(receiver.func).split(".")[-1] in {"Session", "Client", "AsyncClient"}
        if ((name.startswith(("requests.", "httpx.", "session.")) or session_call) and leaf in {"get", "post", "put", "patch", "delete", "head", "request"}
                or name in {"urllib.request.urlopen", "urlopen"}):
            if leaf == "request":
                first = node.args[1] if len(node.args) > 1 else keywords.get("url")
            if first is not None and (self.dynamic(first) or any(
                    token in str(getattr(self.resolve(first), "value", ""))
                    for token in ("169.254.169.254", "127.0.0.1", "localhost", "[::1]"))):
                self.report(Category.SSRF, node)
        if (leaf in {"get", "filter"} and ".objects." in name) or leaf == "get_object_or_404":
            # Only explicit principal scoping is credited; login alone is insufficient.
            scoped = any(any(_name(part) == "request.user" or _name(part).startswith("request.user.")
                             for part in ast.walk(self.resolve(value)))
                         for value in keywords.values())
            for key, value in keywords.items():
                resolved = self.resolve(value)
                if key in {"id", "pk"} and any(
                        _name(part).startswith(("request.GET", "request.POST", "request.args", "request.query_params", "request.data"))
                        for part in ast.walk(resolved)) and not scoped:
                    self.report(Category.IDOR_BOLA, node)
        shell = keywords.get("shell")
        if first is not None and self.dynamic(first) and (
                name in {"os.system", "os.popen"} or
                name in {"eval", "pickle.loads"} or
                name.startswith("subprocess.") and isinstance(shell, ast.Constant) and shell.value is True):
            self.report(Category.COMMAND_INJECTION, node)
        self.generic_visit(node)


class SecureCodingEvaluator:
    def audit_code(self, code: str, filename: str = "snippet.py") -> SecureCodingAuditResult:
        """Audit Python or .html/.htm/.jinja/.jinja2/.j2 templates without execution.

        Empty source is valid. Invalid Python, unsupported types and empty filenames
        raise ValueError. Arbitrary URL validators require manual review.
        """
        if not isinstance(code, str) or not isinstance(filename, str) or not filename.strip() or "\x00" in filename or "\x00" in code:
            raise ValueError("code and filename must be valid strings; filename must be nonempty")
        scanner = _Scanner(code)
        if filename.lower().endswith((".html", ".htm", ".jinja", ".jinja2", ".j2")):
            for match in TEMPLATE_PATTERN.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                severity, requirement, description, guide = RULES[Category.XSS]
                scanner.findings[(line, Category.XSS)] = VulnerabilityFinding(
                    Category.XSS, severity, line, match.group(), description, guide, requirement)
        else:
            try:
                tree = ast.parse(code, filename=filename)
                # Bound recursive visitor work independently of the host's
                # recursion limit (test runners may raise that limit).
                pending = [(tree, 0)]
                while pending:
                    node, depth = pending.pop()
                    if depth > 500:
                        raise ValueError("AST nesting exceeds the analysis limit")
                    pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
                scanner.visit(tree)
            except (SyntaxError, ValueError, RecursionError) as exc:
                raise ValueError("code must be valid Python or use a template filename") from exc
        findings = tuple(value for _, value in sorted(scanner.findings.items()))
        phases = {phase for finding in findings for phase in PHASES[finding.category]}
        return SecureCodingAuditResult(findings,
            max(0.0, round(1 - sum(PENALTIES[f.severity] for f in findings), 10)),
            tuple(phase for phase in KillChainPhase if phase in phases))
