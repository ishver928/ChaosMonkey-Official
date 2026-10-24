"""Python AST detectors — high-precision rules that need real parsing.

These complement the regex rules with structural checks: SQL built by string
formatting into ``execute()``, ``subprocess``/``os.system`` with ``shell=True``,
``eval``/``exec``, unsafe deserialization, Flask ``debug=True``, and ``requests``
``verify=False``. Each returns ``RawMatch`` offsets so the pipeline treats them like
any other detector. Mapped to ``CM-A0xx`` rule ids (new, backend-only).
"""

from __future__ import annotations

import ast

from .common import RawMatch, line_col

# rule id -> (title, category, severity, description, cwe)
AST_RULES = {
    "CM-A001": ("SQL built from string formatting", "injection", "critical",
                "A SQL string assembled with f-strings/format/concat is passed to execute().", "CWE-89"),
    "CM-A002": ("Shell injection via subprocess/os.system", "injection", "critical",
                "subprocess or os.system called with shell=True or a built command string.", "CWE-78"),
    "CM-A003": ("Use of eval/exec", "injection", "high",
                "eval()/exec() on dynamic input runs arbitrary code.", "CWE-94"),
    "CM-A004": ("Unsafe deserialization", "injection", "critical",
                "pickle.load / yaml.load without SafeLoader executes arbitrary objects.", "CWE-502"),
    "CM-A005": ("Flask debug mode enabled", "misc", "high",
                "Flask app.run(debug=True) exposes the Werkzeug debugger (RCE).", "CWE-489"),
    "CM-A006": ("TLS verification disabled (requests)", "storage", "high",
                "requests called with verify=False disables certificate checking.", "CWE-295"),
    "CM-A007": ("Path traversal via open()", "injection", "high",
                "open() on a user-controlled path can read/write arbitrary files.", "CWE-22"),
}


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


def _func_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        parts = []
        cur: ast.AST = f
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _is_dynamic_str(node: ast.AST) -> bool:
    """True if a value is assembled dynamically (f-string, +, %, .format, str.join)."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def detect_python_ast(content: str) -> list[RawMatch]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    starts = _line_starts(content)
    out: list[RawMatch] = []

    def add(rule_id: str, node: ast.AST, conf: float, note: str | None = None):
        s, e = _offset(starts, node)
        out.append(RawMatch(rule_id, s, e, False, conf, note=note))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _func_name(node)

        # CM-A001: SQL via string formatting into execute/executemany
        if name.split(".")[-1] in {"execute", "executemany", "executescript"} and node.args:
            if _is_dynamic_str(node.args[0]):
                add("CM-A001", node, 0.9, "dynamic SQL string in execute()")

        # CM-A002: subprocess/os.system shell injection
        if name in {"os.system", "os.popen"}:
            if node.args and _is_dynamic_str(node.args[0]):
                add("CM-A002", node, 0.9, "os.system with built command")
            elif node.args and not isinstance(node.args[0], ast.Constant):
                add("CM-A002", node, 0.75, "os.system with variable command")
        if name.startswith("subprocess.") or name == "Popen":
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            if shell_true:
                add("CM-A002", node, 0.9, "subprocess with shell=True")

        # CM-A003: eval/exec
        if name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
            add("CM-A003", node, 0.85, f"{name}() on non-literal")

        # CM-A004: unsafe deserialization
        if name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"}:
            add("CM-A004", node, 0.85, "pickle load of untrusted data")
        if name in {"yaml.load"}:
            safe = any(kw.arg == "Loader" and "Safe" in ast.dump(kw.value) for kw in node.keywords)
            if not safe:
                add("CM-A004", node, 0.85, "yaml.load without SafeLoader")

        # CM-A005: Flask debug=True
        if name.endswith(".run") or name == "run":
            if any(kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
                add("CM-A005", node, 0.85, "debug=True")

        # CM-A006: requests verify=False
        if name.startswith("requests.") or name in {"get", "post", "put", "delete", "patch", "request"}:
            if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
                add("CM-A006", node, 0.85, "verify=False")

        # CM-A007: open() on a non-literal path combined with request-ish input
        if name == "open" and node.args and not isinstance(node.args[0], ast.Constant):
            arg_src = ast.dump(node.args[0])
            if any(tok in arg_src for tok in ("request", "args", "params", "filename", "path", "user", "input")):
                add("CM-A007", node, 0.7, "open() on user-controlled path")

    return out
