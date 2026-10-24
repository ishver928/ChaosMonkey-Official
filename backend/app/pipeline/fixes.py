"""FIX GENERATION + verification.

For each finding we try to build a minimal, *mechanical* patch: line edits plus any imports the
new code needs (``import bcrypt``, ``import os`` ...). Rules with no safe mechanical rewrite
(plaintext PII, localStorage, deserialization of pickles, ...) get the reviewed example from
``rules/catalog.json`` as their ``suggested_fix`` instead, with no diff.

Every patch is VERIFIED: applied to a copy, syntax-checked (``ast.parse``; ``node --check``;
TypeScript parser for .ts/.tsx) and re-scanned to confirm the finding is gone. Only then is
``fix_verified`` set. An unverified patch is never shown as a diff.
"""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field

from ..detectors.catalog import rule_info
from ..detectors.masking import scrub
from ..models.schemas import Finding, SourceFile
from .detect import run_detectors_on_file
from .syntax import check_code


@dataclass
class Patch:
    edits: dict[int, str] = field(default_factory=dict)  # 0-based line index -> replacement text
    imports: list[str] = field(default_factory=list)  # lines to add near the top if missing
    note: str = ""


SECRET_RULES = {"CM-S001", "CM-S002", "CM-S003", "CM-S004", "CM-S005", "CM-S006", "CM-S007",
                "CM-S008", "CM-S010", "CM-S011", "CM-S012", "CM-S014", "CM-D004"}
SECRET_DEFAULT_ENV = {
    "CM-S001": "AWS_ACCESS_KEY_ID", "CM-S002": "AWS_SECRET_ACCESS_KEY", "CM-S003": "GITHUB_TOKEN",
    "CM-S004": "STRIPE_SECRET_KEY", "CM-S005": "OPENAI_API_KEY", "CM-S006": "ANTHROPIC_API_KEY",
    "CM-S007": "GOOGLE_API_KEY", "CM-S008": "SLACK_BOT_TOKEN", "CM-S010": "SERVICE_TOKEN",
    "CM-S011": "DATABASE_URL", "CM-S012": "API_TOKEN", "CM-S014": "API_SECRET", "CM-D004": "JWT_SECRET",
}
_STR_LIT = re.compile(r"""(?:\b[rRbBuU]{1,2})?(["'`])(?:\\.|(?!\1).)*\1""")
_JS_LANGS = {"javascript", "typescript"}


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _env_name(raw: str | None, default: str) -> str:
    if not raw:
        return default
    name = re.sub(r"[\"'\]]", "", raw)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    name = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if len(name) < 3 or name in {"KEY", "TOKEN", "SECRET", "CONFIG", "VALUE", "HEADERS"}:
        return default
    return name


def _is_esm(content: str) -> bool:
    return bool(re.search(r"^\s*(?:import\s.+from\s|import\s*['\"]|export\s)", content, re.M))


def _js_import(content: str, name: str, module: str) -> str:
    return f"import {name} from '{module}'" if _is_esm(content) else f"const {name} = require('{module}')"


# --------------------------------------------------------------------------- secrets

def _secret_patch(f: Finding, lines: list[str], content: str) -> Patch | None:
    lang = f.language
    if lang not in {"python", *_JS_LANGS}:
        return None
    idx = f.line - 1
    line = lines[idx]
    col_start = f.column - 1
    col_end = col_start + (f.end - f.start) if f.endLine == f.line else len(line)
    lit = next((m for m in _STR_LIT.finditer(line) if m.start() <= col_start and m.end() >= col_end), None)
    if lit is None:
        return None
    quote = lit.group(1)
    inner = lit.group(0)[lit.group(0).index(quote) + 1:-1]
    raw = content[f.start:f.end]
    if quote == "`" and "${" in inner:
        return None
    target = re.match(r"\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*[:=](?!=)", line)
    key = re.search(r"[\"']([A-Za-z_][\w-]*)[\"']\s*:\s*$", line[: lit.start()])
    env = _env_name(f.name or (key.group(1) if key else None) or (target.group(1) if target else None),
                    SECRET_DEFAULT_ENV.get(f.ruleId, "API_SECRET"))
    if f.ruleId == "CM-S011":
        env = "DATABASE_URL"
    ref = f'os.environ["{env}"]' if lang == "python" else f"process.env.{env}"
    if inner == raw or f.ruleId == "CM-S011":
        replacement = ref
    elif f.ruleId == "CM-S012" and inner.strip().startswith("Bearer"):
        replacement = f'"Bearer " + {ref}' if lang == "python" else f"`Bearer ${{{ref}}}`"
    else:
        return None
    new = line[: lit.start()] + replacement + line[lit.end():]
    return Patch({idx: new}, ["import os"] if lang == "python" else [],
                 note=f"Set {env} in the environment and rotate the exposed value.")


# --------------------------------------------------------------------------- weak password hash

_PY_HASH = re.compile(r"hashlib\.(?:md5|sha1)\(((?:[^()]|\([^()]*\))*)\)(\.hexdigest\(\)|\.digest\(\))?")
_JS_HASH = re.compile(r"(?:crypto\.)?createHash\(\s*['\"](?:md5|sha1)['\"]\s*\)\.update\(((?:[^()]|\([^()]*\))*)\)(?:\.digest\([^)]*\))?")
_OPERAND = r"[\w$.\[\]\"']+(?:\(\))?"


def _later_comparison(lines: list[str], idx: int, var: str, js: bool) -> tuple[int, re.Match[str], bool] | None:
    """A comparison against ``var`` in the next few lines: (line index, match, operand-first?)."""
    ops = r"(===|==|!==|!=)" if js else r"(==|!=)"
    base_indent = len(_indent(lines[idx]))
    name = r"(?<![\w$.])" + re.escape(var) + r"(?![\w$])"
    for j in range(idx + 1, min(len(lines), idx + 8)):
        if lines[j].strip() and len(_indent(lines[j])) < base_indent:
            break  # left the enclosing block
        m = re.search(r"(" + _OPERAND + r")\s*" + ops + r"\s*" + name, lines[j])
        if m and m.group(1) != var:
            return j, m, True
        m = re.search(name + r"\s*" + ops + r"\s*(" + _OPERAND + r")", lines[j])
        if m:
            return j, m, False
    return None


def _py_weak_hash(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    m = _PY_HASH.search(line)
    if not m or not m.group(1).strip():
        return None
    arg = m.group(1).strip()
    if not (arg.endswith(".encode()") or re.fullmatch(r"b[\"'].*[\"']", arg)):
        if not re.fullmatch(r"[A-Za-z_][\w.]*", arg):
            return None
        arg = f"{arg}.encode()"
    after = line[m.end():]
    before = line[: m.start()]
    cmp_after = re.match(r"\s*(==|!=)\s*(" + _OPERAND + r")", after)
    cmp_before = re.search(r"(" + _OPERAND + r")\s*(==|!=)\s*$", before)
    if cmp_after or cmp_before:
        op, other = (cmp_after.group(1), cmp_after.group(2)) if cmp_after else (cmp_before.group(2), cmp_before.group(1))
        check = f"bcrypt.checkpw({arg}, {other}.encode())"
        if op == "!=":
            check = f"not {check}"
        new = (before[: cmp_before.start()] + check + after) if cmp_before else (before + check + after[cmp_after.end():])
        return Patch({idx: new}, ["import bcrypt"], note="Verify with bcrypt.checkpw; stored values must be bcrypt hashes (re-hash on next login). argon2id is an equally good choice.")
    assigned = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*$", before)
    later = _later_comparison(lines, idx, assigned.group(1), js=False) if assigned and not after.strip() else None
    if later:
        # Two-step verify (h = md5(pw); if stored == h): compare with bcrypt.checkpw instead.
        j, cm, operand_first = later
        other = cm.group(1) if operand_first else cm.group(3)
        op = cm.group(2)
        check = f"bcrypt.checkpw({arg}, {other}.encode())"
        if op == "!=":
            check = f"not {check}"
        edits = {idx: f"{_indent(line)}# password is verified with bcrypt.checkpw below",
                 j: lines[j][: cm.start()] + check + lines[j][cm.end():]}
        return Patch(edits, ["import bcrypt"], note="Verify with bcrypt.checkpw; stored values must be bcrypt hashes (re-hash on next login). argon2id is an equally good choice.")
    decode = ".decode()" if m.group(2) == ".hexdigest()" else ""
    new = before + f"bcrypt.hashpw({arg}, bcrypt.gensalt()){decode}" + after
    return Patch({idx: new}, ["import bcrypt"], note="Verify with bcrypt.checkpw(password.encode(), stored_hash.encode()). argon2id (argon2-cffi) is an equally good choice.")


def _enclosing_js_function(lines: list[str], idx: int) -> tuple[int, str] | None:
    """(line index, kind) of the function that encloses line ``idx``; kind in function|arrow|method."""
    depth = 0
    for j in range(idx, -1, -1):
        text = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", lines[j])
        text = re.sub(r"//.*$", "", text)
        segment = text if j != idx else ""
        depth += segment.count("}") - segment.count("{")
        if depth < 0:
            if re.search(r"\bfunction\b", text):
                return j, "function"
            if "=>" in text:
                return j, "arrow"
            if re.match(r"\s*(?:static\s+)?(?:get\s+|set\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{", text) and not re.match(r"\s*(?:if|for|while|switch|catch)\b", text):
                return j, "method"
            depth = 0
    return None


def _make_async(line: str, kind: str) -> str:
    if re.search(r"\basync\b", line):
        return line
    if kind == "function":
        return re.sub(r"\bfunction\b", "async function", line, count=1)
    if kind == "arrow":
        return re.sub(r"(\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>", r"async \1 =>", line, count=1)
    return re.sub(r"^(\s*(?:static\s+)?)", r"\1async ", line, count=1)


def _js_weak_hash(f: Finding, lines: list[str], content: str) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    m = _JS_HASH.search(line)
    if not m or not m.group(1).strip():
        return None
    arg = m.group(1).strip()
    edits: dict[int, str] = {}
    fn = _enclosing_js_function(lines, idx)
    note = "argon2id (argon2 package) is an equally good choice."
    if fn is None:
        if not _is_esm(content):
            return None  # top-level CommonJS: no await available; use the catalog example
    elif not re.search(r"\basync\b", lines[fn[0]]):
        edits[fn[0]] = _make_async(lines[fn[0]], fn[1])
        note = "The enclosing function is now async, so its callers must await it. " + note
    before, after = line[: m.start()], line[m.end():]
    cmp_after = re.match(r"\s*(===|==|!==|!=)\s*(" + _OPERAND + r")", after)
    cmp_before = re.search(r"(" + _OPERAND + r")\s*(===|==|!==|!=)\s*$", before)
    if cmp_after or cmp_before:
        op, other = (cmp_after.group(1), cmp_after.group(2)) if cmp_after else (cmp_before.group(2), cmp_before.group(1))
        check = f"(await bcrypt.compare({arg}, {other}))"
        if op.startswith("!"):
            check = f"!{check}"
        new = (before[: cmp_before.start()] + check + after) if cmp_before else (before + check + after[cmp_after.end():])
    else:
        assigned = re.match(r"\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*$", before)
        later = _later_comparison(lines, idx, assigned.group(1), js=True) if assigned and not after.strip(" ;") else None
        if later:
            # Two-step verify (hash = md5(pw); if (user.hash !== hash)): use bcrypt.compare on that line.
            j, cm, operand_first = later
            other = cm.group(1) if operand_first else cm.group(3)
            check = f"(await bcrypt.compare({arg}, {other}))"
            if cm.group(2).startswith("!"):
                check = f"!{check}"
            edits[idx] = f"{_indent(line)}// password is verified with bcrypt.compare below"
            edits[j] = lines[j][: cm.start()] + check + lines[j][cm.end():]
            return Patch(edits, [_js_import(content, "bcrypt", "bcryptjs")],
                         note="Stored values must be bcrypt hashes (re-hash on next login). " + note)
        new = before + f"await bcrypt.hash({arg}, 12)" + after
    edits[idx] = new
    return Patch(edits, [_js_import(content, "bcrypt", "bcryptjs")],
                 note="Verify with await bcrypt.compare(password, storedHash). " + note)


# --------------------------------------------------------------------------- SQL injection

def _placeholder_style(content: str, lang: str) -> str:
    if lang == "python":
        if re.search(r"^\s*(?:import|from)\s+(?:psycopg2?|pymysql|MySQLdb|mysql\.connector)\b", content, re.M):
            return "%s"
        return "?"
    if re.search(r"require\(['\"](?:pg|postgres)['\"]\)|from\s+['\"](?:pg|postgres)['\"]", content):
        return "$n"
    return "?"


def _py_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


class _Bail(Exception):
    pass


def _sql_parts(node: ast.AST) -> list[tuple[str, str]]:
    """Flatten a dynamic SQL expression into [("text", s) | ("param", src) | ("ident", src)]."""
    from ..detectors.python_ast import _is_upper_const

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("text", node.value)]
    if isinstance(node, ast.JoinedStr):
        out: list[tuple[str, str]] = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                out.append(("text", str(v.value)))
            elif isinstance(v, ast.FormattedValue):
                if v.conversion != -1 or v.format_spec is not None:
                    raise _Bail()
                out.append(("ident" if _is_upper_const(v.value) else "param", ast.unparse(v.value)))
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _sql_parts(node.left) + _sql_parts(node.right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
        values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        chunks = re.split(r"(%[sd])", node.left.value)
        out, vi = [], 0
        for ch in chunks:
            if ch in ("%s", "%d"):
                if vi >= len(values):
                    raise _Bail()
                out.append(("param", ast.unparse(values[vi])))
                vi += 1
            elif ch:
                out.append(("text", ch.replace("%%", "%")))
        return out
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
            and isinstance(node.func.value, ast.Constant) and not node.keywords:
        chunks = re.split(r"(\{\d*\})", node.func.value.value)
        out, vi = [], 0
        for ch in chunks:
            if re.fullmatch(r"\{\d*\}", ch):
                pos = int(ch[1:-1]) if ch[1:-1] else vi
                if pos >= len(node.args):
                    raise _Bail()
                out.append(("param", ast.unparse(node.args[pos])))
                vi += 1
            elif ch:
                out.append(("text", ch))
        return out
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
        from ..detectors.python_ast import _is_upper_const as upper
        return [("ident" if upper(node) else "param", ast.unparse(node))]
    raise _Bail()


def _assemble_sql(parts: list[tuple[str, str]], style: str, lang: str) -> tuple[str, list[str], bool]:
    """Return (query text, params, needs_fstring). Quotes and LIKE wildcards around values move into params."""
    text_parts: list[str] = []
    params: list[str] = []
    has_ident = False
    pending = [list(p) for p in parts]
    for i, (kind, val) in enumerate(pending):
        if kind == "text":
            continue
        if kind == "ident":
            has_ident = True
            continue
        prev = pending[i - 1] if i > 0 and pending[i - 1][0] == "text" else None
        nxt = pending[i + 1] if i + 1 < len(pending) and pending[i + 1][0] == "text" else None
        pre_wild = post_wild = ""
        if prev and nxt:
            if prev[1].endswith("'%") and nxt[1].startswith("%'"):
                prev[1], nxt[1], pre_wild, post_wild = prev[1][:-2], nxt[1][2:], "%", "%"
            elif prev[1].endswith("'") and nxt[1].startswith("'"):
                prev[1], nxt[1] = prev[1][:-1], nxt[1][1:]
        if pre_wild:
            val = f'"%" + str({val}) + "%"' if lang == "python" else f"`%${{{val}}}%`"
        params.append(val)
    n = 0
    for kind, val in pending:
        if kind == "text":
            text_parts.append(val.replace("%", "%%") if style == "%s" else val)
        elif kind == "ident":
            text_parts.append("{" + val + "}" if lang == "python" else "${" + val + "}")
        else:
            n += 1
            text_parts.append(f"${n}" if style == "$n" else style)
    return "".join(text_parts), params, has_ident


def _py_sqli(f: Finding, lines: list[str], content: str) -> Patch | None:
    from ..detectors.python_ast import SQL_SINKS, _func_name, _is_dynamic_str

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    style = _placeholder_style(content, "python")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == f.line and n.end_lineno == f.line
             and _func_name(n).split(".")[-1] in SQL_SINKS and n.args and len(n.args) == 1 and not n.keywords]
    if not calls:
        return None
    call = calls[0]
    arg = call.args[0]
    idx = f.line - 1
    line = lines[idx]
    edits: dict[int, str] = {}
    if _is_dynamic_str(arg):
        source_node, assign_line = arg, None
    elif isinstance(arg, ast.Name):
        # Query text built into a variable first: rewrite that (single-line) assignment too.
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and n.lineno < f.line and n.lineno == n.end_lineno
                   and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == arg.id]
        if not assigns or not _is_dynamic_str(assigns[-1].value):
            return None
        later = [n for n in ast.walk(tree) if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
                 and n.target.id == arg.id and assigns[-1].lineno < n.lineno < f.line]
        if later:
            return None
        source_node, assign_line = assigns[-1].value, assigns[-1].lineno
    else:
        return None
    try:
        query, params, has_ident = _assemble_sql(_sql_parts(source_node), style, "python")
    except _Bail:
        return None
    if not params:
        return None
    if has_ident:
        # Keep UPPER_CASE identifiers (table names) interpolated; everything else is a parameter.
        lit = "f" + _py_quote(re.sub(r"\{\{([A-Z][A-Z0-9_]*)\}\}", r"{\1}", query.replace("{", "{{").replace("}", "}}")))
    else:
        lit = _py_quote(query)
    tuple_src = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    if assign_line is None:
        new = line[: arg.col_offset] + f"{lit}, {tuple_src}" + line[arg.end_col_offset:]
        edits[idx] = new
    else:
        aidx = assign_line - 1
        aline = lines[aidx]
        edits[aidx] = aline[: source_node.col_offset] + lit + aline[source_node.end_col_offset:]
        edits[idx] = line[: arg.end_col_offset] + f", {tuple_src}" + line[arg.end_col_offset:]
    return Patch(edits, note=f"Parameterized query ({'?' if style == '?' else '%s'} placeholders); values are passed separately.")


_JS_TMPL_SQL = re.compile(r"\b(query|execute|raw|run|all|prepare)\s*\(\s*`([^`]*)`\s*\)")
_JS_CONCAT_SQL = re.compile(r"\b(query|execute|raw|run|all|prepare)\s*\(\s*((?:[\"'][^\"'\n]*[\"']|[A-Za-z_$][\w$.\[\]]*)(?:\s*\+\s*(?:[\"'][^\"'\n]*[\"']|[A-Za-z_$][\w$.\[\]]*))+)\s*\)")


def _js_template_parts(tmpl: str) -> list[tuple[str, str]] | None:
    out: list[tuple[str, str]] = []
    pos = 0
    for m in re.finditer(r"\$\{([^}]*)\}", tmpl):
        if m.start() > pos:
            out.append(("text", tmpl[pos:m.start()]))
        expr = m.group(1).strip()
        out.append(("ident" if re.fullmatch(r"[A-Z][A-Z0-9_]*", expr) else "param", expr))
        pos = m.end()
    if pos < len(tmpl):
        out.append(("text", tmpl[pos:]))
    return out


def _js_quote(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _js_sqli(f: Finding, lines: list[str], content: str) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    style = _placeholder_style(content, "javascript")
    m = _JS_TMPL_SQL.search(line)
    parts = None
    if m:
        parts = _js_template_parts(m.group(2))
    else:
        m = _JS_CONCAT_SQL.search(line)
        if m:
            parts = []
            for tok in re.split(r"\s*\+\s*", m.group(2)):
                if tok[:1] in "\"'":
                    parts.append(("text", tok[1:-1]))
                else:
                    parts.append(("ident" if re.fullmatch(r"[A-Z][A-Z0-9_]*", tok) else "param", tok))
    edits: dict[int, str] = {}
    if m and parts:
        query, params, has_ident = _assemble_sql(parts, style, "javascript")
        if has_ident or not params:
            return None
        call = f"{m.group(1)}({_js_quote(query)}, [{', '.join(params)}])"
        edits[idx] = line[: m.start()] + call + line[m.end():]
        return Patch(edits, note="Parameterized query; values are passed separately.")
    # Query text built into a variable first.
    mv = re.search(r"\b(query|execute|raw|run|all|prepare)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", line)
    if not mv:
        return None
    name = mv.group(2)
    for j in range(idx - 1, -1, -1):
        am = re.match(r"(\s*(?:const|let|var)\s+" + re.escape(name) + r"\s*=\s*)`([^`]*)`(\s*;?\s*)$", lines[j])
        if am:
            parts = _js_template_parts(am.group(2))
            query, params, has_ident = _assemble_sql(parts or [], style, "javascript")
            if has_ident or not params:
                return None
            edits[j] = am.group(1) + _js_quote(query) + am.group(3)
            edits[idx] = line[: mv.end() - 1] + f", [{', '.join(params)}])" + line[mv.end():]
            return Patch(edits, note="Parameterized query; values are passed separately.")
        if re.search(r"\b" + re.escape(name) + r"\b", lines[j]):
            return None
    return None


# --------------------------------------------------------------------------- command injection

_SHELL_META = re.compile(r"[|&;<>$`*?(){}\[\]~\"'\\]")


def _argv_from_parts(parts: list[tuple[str, str]], lang: str) -> list[str] | None:
    tokens: list[list[tuple[str, str]]] = [[]]
    for kind, val in parts:
        if kind == "text":
            if _SHELL_META.search(val):
                return None
            pieces = re.split(r"(\s+)", val)
            for p in pieces:
                if not p:
                    continue
                if p.isspace():
                    tokens.append([])
                else:
                    tokens[-1].append(("text", p))
        else:
            tokens[-1].append(("expr", val))
    out = []
    for tok in tokens:
        if not tok:
            continue
        if len(tok) == 1:
            kind, val = tok[0]
            out.append((_py_quote(val) if lang == "python" else _js_quote(val)) if kind == "text" else val)
        elif lang == "python":
            out.append("f" + _py_quote("".join(v.replace("{", "{{").replace("}", "}}") if k == "text" else "{" + v + "}" for k, v in tok)))
        else:
            out.append("`" + "".join(v if k == "text" else "${" + v + "}" for k, v in tok) + "`")
    return out or None


def _py_cmd(f: Finding, lines: list[str], content: str) -> Patch | None:
    from ..detectors.python_ast import _func_name

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    idx = f.line - 1
    line = lines[idx]
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and call.lineno == f.line and call.end_lineno == f.line and call.args):
            continue
        name = _func_name(call)
        arg = call.args[0]
        try:
            parts = _sql_parts(arg)
        except _Bail:
            continue
        argv = _argv_from_parts(parts, "python")
        if not argv:
            continue
        lst = "[" + ", ".join(argv) + "]"
        if name == "os.system":
            new = line[: call.col_offset] + f"subprocess.run({lst}, check=False).returncode" + line[call.end_col_offset:]
            return Patch({idx: new}, ["import subprocess"], note="Arguments are passed as a list with no shell, so input can't inject commands.")
        if name.startswith("subprocess.") or name in {"run", "Popen", "call", "check_output", "check_call"}:
            seg = line[call.col_offset: call.end_col_offset]
            rel_a, rel_b = arg.col_offset - call.col_offset, arg.end_col_offset - call.col_offset
            seg = seg[:rel_a] + lst + seg[rel_b:]
            seg = re.sub(r"shell\s*=\s*True", "shell=False", seg)
            return Patch({idx: line[: call.col_offset] + seg + line[call.end_col_offset:]}, note="Arguments are passed as a list with shell=False.")
    return None


def _js_cmd(f: Finding, lines: list[str], content: str) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    m = re.search(r"(?<![\w.$])((?:child_process|cp|childProcess)\.)?exec(Sync)?\s*\(\s*`([^`]*)`", line)
    if not m:
        return None
    parts = _js_template_parts(m.group(3)) or []
    argv = _argv_from_parts([(k if k == "text" else "expr", v) for k, v in parts], "javascript")
    if not argv or len(argv) < 1 or argv[0].startswith("`"):
        return None
    fn = ("execFileSync" if m.group(2) else "execFile")
    prefix = m.group(1) or ""
    new_call = f"{prefix}{fn}({argv[0]}, [{', '.join(argv[1:])}]"
    edits = {idx: line[: m.start()] + new_call + line[m.end():]}
    if not prefix:
        # Make sure execFile is imported next to exec.
        for j, other in enumerate(lines):
            dm = re.match(r"(\s*(?:const|let|var)\s*\{)([^}]*)(\}\s*=\s*require\(['\"](?:node:)?child_process['\"]\).*)$", other) or \
                re.match(r"(\s*import\s*\{)([^}]*)(\}\s*from\s*['\"](?:node:)?child_process['\"].*)$", other)
            if dm:
                names = [n.strip() for n in dm.group(2).split(",") if n.strip()]
                if fn not in names:
                    names.append(fn)
                    edits[j] = f"{dm.group(1)} {', '.join(names)} {dm.group(3)}"
                break
        else:
            return None
    return Patch(edits, note="execFile runs the program directly with an argument array; no shell parses the input.")


# --------------------------------------------------------------------------- XSS

def _py_xss(f: Finding, lines: list[str], content: str) -> Patch | None:
    from ..detectors.python_ast import _is_request_expr, _scope_map, _tainted_names

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    scopes = _scope_map(tree)
    tainted_by_scope, _html = _tainted_names(tree, scopes)
    idx = f.line - 1
    line = lines[idx]
    targets = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) != f.line or getattr(node, "end_lineno", None) != f.line:
            continue
        tainted = tainted_by_scope.get(id(scopes.get(id(node), tree)), set())
        if isinstance(node, ast.FormattedValue):
            expr = node.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for side in (node.left, node.right):
                if not isinstance(side, (ast.Constant, ast.BinOp, ast.JoinedStr)) and \
                        ((isinstance(side, ast.Name) and side.id in tainted) or _is_request_expr(side)):
                    targets.append(side)
            continue
        else:
            continue
        if (isinstance(expr, ast.Name) and expr.id in tainted) or _is_request_expr(expr):
            targets.append(expr)
    if not targets:
        return None
    new = line
    for t in sorted({(t.col_offset, t.end_col_offset) for t in targets}, reverse=True):
        new = new[: t[0]] + f"escape({new[t[0]:t[1]]})" + new[t[1]:]
    return Patch({idx: new}, ["from markupsafe import escape"], note="Values are HTML-escaped before they reach the page.")


_ESCAPE_HELPER = ("const escapeHtml = (s) => String(s).replace(/[&<>\"']/g, (c) => "
                  "({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' })[c])")


def _js_reflected_xss(f: Finding, lines: list[str], content: str) -> Patch | None:
    from ..detectors.js_rules import _expr_tainted, _tainted_js

    idx = f.line - 1
    line = lines[idx]
    tainted = _tainted_js(content)
    m = re.search(r"\bres\.(?:send|write|end)\s*\(", line)
    if not m:
        return None
    rest = line[m.end():]
    if rest.lstrip().startswith("`"):
        new_rest = re.sub(r"\$\{([^}]*)\}", lambda x: "${escapeHtml(" + x.group(1).strip() + ")}" if _expr_tainted(x.group(1), tainted) else x.group(0), rest)
    else:
        call_body = re.match(r"([^)]*)\)", rest)
        if not call_body:
            return None
        ops = re.split(r"(\s*\+\s*)", call_body.group(1))
        ops = [("escapeHtml(" + o.strip() + ")") if (o.strip() and not re.match(r"\s*\+\s*$", o) and o.strip()[:1] not in "\"'" and _expr_tainted(o, tainted)) else o for o in ops]
        new_rest = "".join(ops) + rest[call_body.end() - 1:]
    if new_rest == rest:
        return None
    imports = [] if "escapeHtml" in content else [_ESCAPE_HELPER]
    return Patch({idx: line[: m.end()] + new_rest}, imports, note="Request values are HTML-escaped before they are sent.")


# --------------------------------------------------------------------------- config / misc

def _cookie_flags(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    if "document.cookie" in line:
        return None
    from ..detectors.rules import call_end

    if f.language == "python":
        m = re.search(r"\.set_cookie\s*\(", line)
        if not m:
            return None
        end = call_end(line, m.end() - 1)
        if end > len(line) or line[end - 1] != ")":
            return None
        call = line[m.start(): end]
        add = []
        if not re.search(r"httponly\s*=\s*True", call, re.I):
            add.append("httponly=True")
        if not re.search(r"secure\s*=\s*True", call, re.I):
            add.append("secure=True")
        if not re.search(r"samesite\s*=", call, re.I):
            add.append('samesite="Lax"')
        if not add:
            return None
        return Patch({idx: line[: end - 1] + ", " + ", ".join(add) + line[end - 1:]})
    m = re.search(r"\b(?:res|response|ctx|reply)\.(?:cookie|setCookie)\s*\(", line)
    if not m:
        return None
    end = call_end(line, m.end() - 1)
    if end > len(line) or line[end - 1] != ")":
        return None
    call = line[m.start(): end]
    flags = {"httpOnly": "httpOnly: true", "secure": "secure: true", "sameSite": "sameSite: 'lax'"}
    missing = [v for k, v in flags.items() if not re.search(k + r"\s*:" + (r"\s*true" if k != "sameSite" else ""), call, re.I)]
    if not missing:
        return None
    brace = call.find("{")
    if brace >= 0:
        pos = m.start() + brace + 1
        return Patch({idx: line[:pos] + " " + ", ".join(missing) + "," + line[pos:]})
    return Patch({idx: line[: end - 1] + ", { " + ", ".join(missing) + " }" + line[end - 1:]})


def _tls(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    if "NODE_TLS_REJECT_UNAUTHORIZED" in line and f.language in _JS_LANGS:
        return Patch({idx: _indent(line) + "// Removed NODE_TLS_REJECT_UNAUTHORIZED=0: keep certificate verification on (use NODE_EXTRA_CA_CERTS for a private CA)."})
    subs = [
        (r"\bverify\s*=\s*False\b", "verify=True"),
        (r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true"),
        (r"strictSSL\s*:\s*false", "strictSSL: true"),
        (r"ssl\._create_unverified_context\(", "ssl.create_default_context("),
        (r"\bCERT_NONE\b", "CERT_REQUIRED"),
        (r"\.check_hostname\s*=\s*False\b", ".check_hostname = True"),
        (r"\s(?:-k|--insecure)\b", ""),
    ]
    new = line
    for pat, rep in subs:
        new = re.sub(pat, rep, new)
    return Patch({idx: new}) if new != line else None


def _debug_flag(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    if f.ruleId == "CM-A005":
        new = re.sub(r"debug\s*=\s*True", 'debug=os.environ.get("FLASK_DEBUG") == "1"', line)
        return Patch({idx: new}, ["import os"]) if new != line else None
    m = re.match(r"(\s*)DEBUG\s*=\s*True\b(.*)$", line)
    if m:
        return Patch({idx: f'{m.group(1)}DEBUG = os.environ.get("DEBUG") == "1"{m.group(2)}'}, ["import os"])
    new = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", line)
    new = re.sub(r"(\.debug\s*=\s*)True\b", r"\1False", new)
    new = re.sub(r"(\[\s*[\"']DEBUG[\"']\s*\]\s*=\s*)True\b", r"\1False", new)
    return Patch({idx: new}) if new != line else None


def _cors(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    if f.language == "python":
        env = 'os.environ.get("ALLOWED_ORIGINS", "").split(",")'
        new = re.sub(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]", f"allow_origins={env}", line)
        new = re.sub(r"\borigins\s*=\s*[\"']\*[\"']", f"origins={env}", new)
        new = re.sub(r"\bCORS\(\s*(\w+)\s*\)", rf"CORS(\1, origins={env})", new)
        return Patch({idx: new}, ["import os"]) if new != line else None
    env = "(process.env.ALLOWED_ORIGINS || '').split(',')"
    new = re.sub(r"\borigin\s*:\s*(?:[\"']\*[\"']|true\b)", f"origin: {env}", line)
    new = re.sub(r"\bcors\(\s*\)", f"cors({{ origin: {env} }})", new)
    return Patch({idx: new}) if new != line else None


def _simple_subs(f: Finding, lines: list[str]) -> Patch | None:
    idx = f.line - 1
    line = lines[idx]
    if f.ruleId == "CM-A003":
        if re.search(r"(?<![\w.])exec\s*\(", line):
            return None
        new = re.sub(r"(?<![\w.])eval\s*\(", "ast.literal_eval(", line)
        return Patch({idx: new}, ["import ast"]) if new != line else None
    if f.ruleId == "CM-A004":
        new = re.sub(r"\byaml\.load\(\s*([^,()]+?)\s*(?:,\s*Loader\s*=\s*[\w.]+\s*)?\)", r"yaml.safe_load(\1)", line)
        return Patch({idx: new}) if new != line else None
    if f.ruleId == "CM-J001":
        new = re.sub(r"\.innerHTML(\s*=(?!=))", r".textContent\1", line)
        return Patch({idx: new}) if new != line and "+=" not in line else None
    if f.ruleId == "CM-J005":
        new = re.sub(r"\bjwt\.decode\s*\(\s*([^,()]+?)\s*\)", r"jwt.verify(\1, process.env.JWT_SECRET, { algorithms: ['HS256'] })", line)
        return Patch({idx: new}) if new != line else None
    if f.ruleId == "CM-C002" and f.language == "python":
        new = re.sub(r"(?<![\w.])random\.(choice|choices|sample)\s*\(", r"secrets.SystemRandom().\1(", line)
        new = re.sub(r"(?<![\w.])random\.randint\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)", r"secrets.SystemRandom().randint(\1, \2)", new)
        return Patch({idx: new}, ["import secrets"]) if new != line else None
    return None


def build_patch(finding: Finding, sf: SourceFile) -> Patch | None:
    """Mechanical patch for a finding, or None when only manual guidance is safe."""
    lines = sf.content.split("\n")
    if not (0 < finding.line <= len(lines)):
        return None
    rid, lang = finding.ruleId, finding.language
    try:
        if rid in SECRET_RULES:
            return _secret_patch(finding, lines, sf.content)
        if rid == "CM-D002":
            return _py_weak_hash(finding, lines) if lang == "python" else (_js_weak_hash(finding, lines, sf.content) if lang in _JS_LANGS else None)
        if rid == "CM-A001":
            return _py_sqli(finding, lines, sf.content)
        if rid == "CM-J003":
            return _js_sqli(finding, lines, sf.content)
        if rid == "CM-A002":
            return _py_cmd(finding, lines, sf.content)
        if rid == "CM-J002":
            return _js_cmd(finding, lines, sf.content)
        if rid == "CM-A008":
            return _py_xss(finding, lines, sf.content)
        if rid == "CM-J006":
            return _js_reflected_xss(finding, lines, sf.content)
        if rid == "CM-D005":
            return _cookie_flags(finding, lines)
        if rid in {"CM-D007", "CM-A006"}:
            return _tls(finding, lines)
        if rid in {"CM-A005", "CM-C003"}:
            return _debug_flag(finding, lines)
        if rid in {"CM-J004", "CM-C004"}:
            return _cors(finding, lines)
        return _simple_subs(finding, lines)
    except Exception:  # pragma: no cover - a fixer bug must never break a scan
        return None


def _has_import(content: str, imp: str) -> bool:
    if imp.startswith("const escapeHtml"):
        return "escapeHtml" in content
    norm = re.escape(imp).replace(r"\ ", r"\s+")
    if re.search(r"^\s*" + norm + r"\s*;?\s*$", content, re.M):
        return True
    m = re.match(r"import (\w+)$", imp)
    if m and re.search(rf"^\s*import\s+(?:[\w.]+\s*,\s*)*{m.group(1)}\b", content, re.M):
        return True
    m = re.match(r"(?:const (\w+) = require|import (\w+) from)", imp)
    if m:
        name = m.group(1) or m.group(2)
        return bool(re.search(rf"\b(?:const|let|var|import)\s+{name}\b", content))
    return False


def _insert_imports(lines: list[str], imports: list[str], language: str) -> list[str]:
    content = "\n".join(lines)
    todo = [imp for imp in dict.fromkeys(imports) if not _has_import(content, imp)]
    if not todo:
        return lines
    at = 0
    if lines and lines[0].startswith("#!"):
        at = 1
    if language == "python":
        try:
            tree = ast.parse(content)
            body = tree.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                at = max(at, body[0].end_lineno or 0)
            for node in body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    at = max(at, node.end_lineno or node.lineno)
                elif not (isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant)):
                    break
        except SyntaxError:
            pass
    else:
        for i, ln in enumerate(lines):
            if re.match(r"\s*(?:import\s|const\s+.+=\s*require\(|['\"]use strict['\"])", ln):
                at = i + 1
            elif ln.strip() and not ln.strip().startswith("//"):
                break
    return lines[:at] + todo + lines[at:]


def apply_patch(content: str, patch: Patch, language: str) -> str:
    lines = content.split("\n")
    for idx in sorted(patch.edits, reverse=True):
        lines[idx] = patch.edits[idx]
    lines = "\n".join(lines).split("\n")
    return "\n".join(_insert_imports(lines, patch.imports, language))


def patched_content(finding: Finding, sf: SourceFile) -> tuple[str, Patch] | None:
    patch = build_patch(finding, sf)
    if patch is None or not patch.edits:
        return None
    return apply_patch(sf.content, patch, finding.language), patch


def _masked(text: str, finding: Finding, sf: SourceFile) -> str:
    if finding.sensitive and finding.end > finding.start:
        raw = sf.content[finding.start:finding.end]
        if raw and finding.maskedValue:
            text = text.replace(raw, finding.maskedValue)
    return scrub(text)


def generate_fix(finding: Finding, sf: SourceFile, project: list[SourceFile]) -> Finding:
    """Produce and verify a patch for one finding (mutates and returns it)."""
    info = rule_info(finding.ruleId)
    example = info.fix_example(finding.language) if info else ""
    finding.suggested_fix = finding.suggested_fix or example or "Review and remediate manually."
    result = patched_content(finding, sf)
    if result is None:
        finding.fix_verified = False
        finding.fix_diff = ""
        return finding
    new_content, patch = result
    ok, err = check_code(new_content, finding.language, sf.path)
    verified = False
    if ok:
        remaining = run_detectors_on_file(SourceFile(path=sf.path, content=new_content), project, {finding.ruleId})
        verified = not any(f.ruleId == finding.ruleId and f.line == finding.line for f in remaining)
    finding.fix_verified = verified
    if not verified:
        # Never show a patch that doesn't parse, couldn't be checked, or doesn't remove the finding.
        finding.fix_diff = ""
        finding.validation.notes.append(
            "mechanical fix rejected: " + (err or "finding still present after patch") if ok is not None
            else f"mechanical fix not shown: {err}")
        return finding
    diff = "\n".join(difflib.unified_diff(
        sf.content.split("\n"), new_content.split("\n"),
        fromfile=f"a/{sf.path}", tofile=f"b/{sf.path}", lineterm="",
    ))
    finding.fix_diff = _masked(diff, finding, sf)
    changed = [new_content.split("\n")[i] for i in range(len(new_content.split("\n")))
               if i >= len(sf.content.split("\n")) or new_content.split("\n")[i] != sf.content.split("\n")[i]]
    snippet = "\n".join(patch.imports + [patch.edits[i].strip() for i in sorted(patch.edits)])
    finding.suggested_fix = _masked(snippet, finding, sf) if changed else finding.suggested_fix
    finding.fix_note = patch.note
    return finding


def apply_all_fixes(findings: list[Finding], files: dict[str, SourceFile]) -> tuple[dict[str, str], str]:
    """Apply every verified fix to a patched copy. Returns (patched_contents, combined_diff)."""
    patched: dict[str, str] = {p: sf.content for p, sf in files.items()}
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.fix_verified and f.fix_diff:
            by_file.setdefault(f.file, []).append(f)
    for path, fs in by_file.items():
        lang = fs[0].language
        imports: list[str] = []
        # Highest line first so earlier edits don't shift later line numbers.
        for f in sorted(fs, key=lambda x: -x.line):
            current = SourceFile(path=path, content=patched[path])
            patch = build_patch(f, current) if f.line <= len(current.content.split("\n")) else None
            if patch is None:
                continue
            lines = current.content.split("\n")
            for idx in sorted(patch.edits, reverse=True):
                lines[idx] = patch.edits[idx]
            patched[path] = "\n".join(lines)
            imports += patch.imports
        patched[path] = "\n".join(_insert_imports(patched[path].split("\n"), imports, lang))
        ok, _err = check_code(patched[path], lang, path)
        if ok is False:
            patched[path] = files[path].content  # combined edits clashed: keep the file untouched

    combined = []
    for path in sorted(patched):
        if patched[path] != files[path].content:
            combined.extend(difflib.unified_diff(
                files[path].content.split("\n"), patched[path].split("\n"),
                fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
            ))
    return patched, "\n".join(combined)
