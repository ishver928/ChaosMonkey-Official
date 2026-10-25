"""Python AST detectors — high-precision rules that need real parsing.

These complement the regex rules with structural checks: SQL built by string
formatting into a query call, ``subprocess``/``os.system`` with a built command,
``eval``/``exec``, unsafe deserialization, Flask ``debug=True``, ``requests``
``verify=False``, path traversal and reflected XSS. Each returns ``RawMatch`` offsets so the
pipeline treats them like any other detector. Metadata (title, CWE, severity) lives in
``rules/catalog.json``; the frontend has regex ports of the same rules in ``codeRules.ts``.
"""

from __future__ import annotations

import ast
import re

from .catalog import load_catalog
from .common import RawMatch

AST_RULE_IDS = ("CM-A001", "CM-A002", "CM-A003", "CM-A004", "CM-A005", "CM-A006", "CM-A007", "CM-A008")


def _ast_rules() -> dict[str, tuple[str, str, str, str, str]]:
    cat = load_catalog()
    return {rid: (cat[rid].title, cat[rid].category, cat[rid].severity, cat[rid].description, cat[rid].cwe)
            for rid in AST_RULE_IDS}


# rule id -> (title, category, severity, description, cwe); kept for backwards compatibility.
AST_RULES = _ast_rules()

SQL_SINKS = {"execute", "executemany", "executescript", "read_sql", "read_sql_query", "raw"}
_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|replace|create|drop|alter|where|from)\b", re.I)
_HTML_TAG = re.compile(r"<\s*[a-zA-Z/!]")
_ESCAPERS = {"escape", "html.escape", "markupsafe.escape", "bleach.clean", "quote", "conditional_escape"}
_REQUEST_ATTRS = {"args", "form", "values", "cookies", "headers", "json", "data", "files", "get_json", "query_params", "path_params"}


def _offset(lines_idx: list[int], node: ast.AST) -> tuple[int, int]:
    """Absolute (start, end) offsets for an AST node using precomputed line starts."""
    start = lines_idx[node.lineno - 1] + node.col_offset
    end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
    end_col = getattr(node, "end_col_offset", node.col_offset) or node.col_offset
    end = lines_idx[end_line - 1] + end_col
    return start, end


def _line_starts(content: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _dotted(node: ast.AST) -> str:
    parts = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        parts.append(_dotted(cur.func) + "()")
    return ".".join(reversed(parts))


def _func_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, (ast.Attribute, ast.Name)):
        return _dotted(f)
    return ""


def _is_upper_const(node: ast.AST) -> bool:
    """Module-level constants such as TABLE are not user input."""
    return isinstance(node, ast.Name) and node.id.isupper() and len(node.id) > 1


def _str_consts(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _is_dynamic_str(node: ast.AST) -> bool:
    """True if a value is assembled from non-constant parts (f-string, +, %, .format).

    Interpolating only UPPER_CASE constants does not count: that is not user input.
    """
    if isinstance(node, ast.JoinedStr):  # f-string
        vals = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return bool(vals) and not all(_is_upper_const(v) for v in vals)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        operands = _binop_operands(node)
        has_str = any(isinstance(o, (ast.Constant, ast.JoinedStr)) for o in operands)
        dynamic = [o for o in operands if not isinstance(o, ast.Constant) and not _is_upper_const(o)]
        if isinstance(node.op, ast.Mod) and isinstance(node.right, ast.Tuple):
            dynamic = [e for e in node.right.elts if not isinstance(e, ast.Constant) and not _is_upper_const(e)]
        return has_str and bool(dynamic)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        args = list(node.args) + [k.value for k in node.keywords]
        return any(not isinstance(a, ast.Constant) and not _is_upper_const(a) for a in args)
    return False


def _binop_operands(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _binop_operands(node.left) + _binop_operands(node.right)
    return [node]


def _is_request_expr(node: ast.AST) -> bool:
    """request.args / request.form.get(...) / request.json[...] and friends."""
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr in _REQUEST_ATTRS:
            base = n.value
            if isinstance(base, ast.Name) and base.id == "request":
                return True
    return False


def _scope_map(tree: ast.AST) -> dict[int, ast.AST]:
    """id(node) -> innermost enclosing function (or the module) for every node."""
    out: dict[int, ast.AST] = {}

    def visit(node: ast.AST, scope: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            out[id(child)] = scope
            visit(child, child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) else scope)

    visit(tree, tree)
    return out


def _tainted_names(tree: ast.AST, scopes: dict[int, ast.AST]) -> tuple[dict[int, set[str]], dict[int, set[str]]]:
    """Per scope: names holding request data, and names holding HTML built from request data.

    Taint flows through assignments in source order within a function (one pass), stopping
    at escaping/conversion calls, so ``path = os.path.join(base, name)`` stays tainted while
    ``safe = escape(name)`` does not.
    """
    tainted: dict[int, set[str]] = {}
    html: dict[int, set[str]] = {}
    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AugAssign))]
    assigns.sort(key=lambda n: (n.lineno, n.col_offset))
    for node in assigns:
        scope = id(scopes.get(id(node), tree))
        t = tainted.setdefault(scope, set())
        h = html.setdefault(scope, set())
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [x.id for x in targets if isinstance(x, ast.Name)]
        if not names:
            continue
        value = node.value
        is_tainted = _unescaped_taint(value, t)
        builds_html = bool(_HTML_TAG.search(_str_consts(value))) and _unescaped_taint(value, t)
        for name in names:
            if is_tainted:
                t.add(name)
            if builds_html or (isinstance(node, ast.AugAssign) and name in h):
                h.add(name)
            elif isinstance(node, ast.AugAssign) and builds_html:
                h.add(name)
    return tainted, html


def _unescaped_taint(node: ast.AST, tainted: set[str]) -> bool:
    """True if ``node`` uses request data or a tainted name outside an escaping call."""
    def visit(n: ast.AST) -> bool:
        if isinstance(n, ast.Call) and _func_name(n) in _ESCAPERS | {"int", "float", "len", "bool", "secure_filename"}:
            return False
        if isinstance(n, ast.Name) and n.id in tainted:
            return True
        if _is_request_expr(n) and isinstance(n, ast.Attribute):
            return True
        return any(visit(c) for c in ast.iter_child_nodes(n))
    return visit(node)


def _path_taint(node: ast.AST, tainted: set[str]) -> bool:
    """Request data reaches a filesystem path without basename()/secure_filename()."""
    def visit(n: ast.AST) -> bool:
        if isinstance(n, ast.Call) and _func_name(n).split(".")[-1] in {"basename", "secure_filename"}:
            return False
        if isinstance(n, ast.Name) and n.id in tainted:
            return True
        if isinstance(n, ast.Attribute) and _is_request_expr(n):
            return True
        return any(visit(c) for c in ast.iter_child_nodes(n))
    return visit(node)


def _guarded_paths(tree: ast.AST, scopes: dict[int, ast.AST]) -> dict[int, set[str]]:
    """Per scope: names whose containment is checked (startswith / is_relative_to / commonpath)."""
    out: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        short = _func_name(node).split(".")[-1]
        names: list[str] = []
        if short in {"startswith", "is_relative_to", "relative_to"} and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                names.append(node.func.value.id)
        if short == "commonpath":
            names += [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
        if names:
            out.setdefault(id(scopes.get(id(node), tree)), set()).update(names)
    return out


def _builds_tainted_html(v: ast.AST, tainted: set[str]) -> bool:
    if isinstance(v, (ast.JoinedStr, ast.BinOp)) or (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "format"):
        return bool(_HTML_TAG.search(_str_consts(v))) and _unescaped_taint(v, tainted)
    return False


def _sql_assignments(tree: ast.AST, scopes: dict[int, ast.AST]) -> dict[tuple[int, str], list[tuple[int, bool]]]:
    """(scope, name) -> [(line, is_dynamic_sql)] for every assignment, in source order."""
    out: dict[tuple[int, str], list[tuple[int, bool]]] = {}
    for node in ast.walk(tree):
        scope = id(scopes.get(id(node), tree))
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            dyn = _is_dynamic_str(node.value) and bool(_SQL_WORDS.search(_str_consts(node.value)))
            out.setdefault((scope, node.targets[0].id), []).append((node.lineno, dyn))
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            key = (scope, node.target.id)
            if out.get(key) and not isinstance(node.value, ast.Constant):
                out[key].append((node.lineno, any(d for _l, d in out[key])))
    for v in out.values():
        v.sort()
    return out


def _built_sql(name: str, line: int, scope: int, assigns: dict) -> bool:
    """True if the latest assignment to ``name`` before ``line`` in this scope built dynamic SQL."""
    prior = [d for ln, d in assigns.get((scope, name), []) if ln <= line]
    return bool(prior) and prior[-1]


def detect_python_ast(content: str) -> list[RawMatch]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    starts = _line_starts(content)
    out: list[RawMatch] = []
    scopes = _scope_map(tree)
    tainted_by_scope, html_by_scope = _tainted_names(tree, scopes)
    assigns = _sql_assignments(tree, scopes)
    guarded_by_scope = _guarded_paths(tree, scopes)

    def add(rule_id: str, node: ast.AST, conf: float, note: str | None = None):
        s, e = _offset(starts, node)
        out.append(RawMatch(rule_id, s, e, False, conf, note=note))

    for node in ast.walk(tree):
        scope = id(scopes.get(id(node), tree))
        tainted = tainted_by_scope.get(scope, set())
        html_vars = html_by_scope.get(scope, set())
        # CM-A008: returning HTML built from request data without escaping.
        if isinstance(node, ast.Return) and node.value is not None:
            v = node.value
            if isinstance(v, ast.Tuple) and v.elts:
                v = v.elts[0]
            if _builds_tainted_html(v, tainted) or (isinstance(v, ast.Name) and v.id in html_vars):
                add("CM-A008", v, 0.8, "request data returned in HTML unescaped")
            continue
        if not isinstance(node, ast.Call):
            continue
        name = _func_name(node)
        short = name.split(".")[-1]

        # CM-A001: SQL via string formatting into a query sink
        if short in SQL_SINKS and node.args:
            arg = node.args[0]
            if _is_dynamic_str(arg) and (short.startswith("execute") or _SQL_WORDS.search(_str_consts(arg))):
                add("CM-A001", node, 0.9, "dynamic SQL string in query call")
            elif isinstance(arg, ast.Name) and _built_sql(arg.id, node.lineno, scope, assigns):
                add("CM-A001", node, 0.85, f"query string `{arg.id}` built dynamically")
        if short == "text" and node.args and _is_dynamic_str(node.args[0]) and _SQL_WORDS.search(_str_consts(node.args[0])):
            add("CM-A001", node, 0.85, "dynamic SQL passed to text()")

        # CM-A002: subprocess/os.system shell injection (a constant command is not injectable)
        if name in {"os.system", "os.popen"} and node.args and not isinstance(node.args[0], ast.Constant):
            dyn = _is_dynamic_str(node.args[0])
            if dyn or not _is_upper_const(node.args[0]):
                add("CM-A002", node, 0.9 if dyn else 0.75, "os.system with built command" if dyn else "os.system with variable command")
        if name.startswith("subprocess.") or name in {"Popen", "run", "call", "check_output", "check_call"}:
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            if shell_true and node.args and not isinstance(node.args[0], ast.Constant) and not _is_upper_const(node.args[0]):
                add("CM-A002", node, 0.9, "subprocess with shell=True and a non-constant command")

        # CM-A003: eval/exec
        if name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
            add("CM-A003", node, 0.85, f"{name}() on non-literal")

        # CM-A004: unsafe deserialization
        if name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads",
                    "marshal.load", "marshal.loads", "jsonpickle.decode", "yaml.unsafe_load", "pickle.Unpickler",
                    "shelve.open"}:
            add("CM-A004", node, 0.85, f"{name} of untrusted data")
        if name in {"yaml.load", "yaml.load_all"}:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            loader_src = _dotted(loader) if loader is not None else ""
            if "Safe" not in loader_src:
                add("CM-A004", node, 0.85, "yaml.load without SafeLoader")

        # CM-A005: Flask debug=True
        if name.endswith(".run") or name == "run":
            if any(kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
                add("CM-A005", node, 0.85, "debug=True")

        # CM-A006: requests verify=False
        if name.startswith("requests.") or name.startswith("httpx.") or name in {"get", "post", "put", "delete", "patch", "request"}:
            if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
                add("CM-A006", node, 0.85, "verify=False")

        # CM-A007: open() on a path built from request data (not merely a variable named "path")
        if name in {"open", "send_file", "io.open"} and node.args and not isinstance(node.args[0], ast.Constant):
            a0 = node.args[0]
            guarded = isinstance(a0, ast.Name) and a0.id in guarded_by_scope.get(scope, set())
            if not guarded and _path_taint(a0, tainted):
                add("CM-A007", node, 0.75, "open() on user-controlled path")

        # CM-A008: render_template_string / Markup on request data
        if short == "render_template_string" and node.args:
            arg = node.args[0]
            if _is_dynamic_str(arg) or _unescaped_taint(arg, tainted):
                add("CM-A008", node, 0.85, "render_template_string with request data")
        if short in {"Markup", "mark_safe"} and node.args and _unescaped_taint(node.args[0], tainted):
            add("CM-A008", node, 0.8, f"{short}() on request data")
        if short in {"Response", "make_response", "HTMLResponse"} and node.args:
            a0 = node.args[0]
            if _builds_tainted_html(a0, tainted) or (isinstance(a0, ast.Name) and a0.id in html_vars):
                add("CM-A008", node, 0.8, f"{short}() with HTML built from request data")

    return out
