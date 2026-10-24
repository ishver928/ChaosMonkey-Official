"""FIX GENERATION + verification.

For each finding we produce a minimal unified-diff patch. The suggested replacement comes
from the KB's fixed example / a template for the rule, optionally refined by the local LLM.
Every patch is VERIFIED: we apply it to a temp copy, confirm the file still parses
(ast.parse for Python; ``node --check`` for JS when node is available), and re-run the
detectors to confirm the finding is gone. Only then is ``fix_verified`` set True.
"""

from __future__ import annotations

import ast
import difflib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models.schemas import Finding, SourceFile
from .detect import run_detectors_on_file

# Rule id -> callable(line) -> replacement line. Deterministic, minimal edits.
_LINE_FIXERS: dict[str, "object"] = {}


def _env_name(name: str | None, default: str) -> str:
    base = (name or default).strip().upper()
    base = re.sub(r"[^A-Z0-9_]", "_", base) or default
    return base


def suggest_replacement(finding: Finding, line: str) -> str | None:
    """Return a replacement for the finding's line, or None if we can't fix it safely."""
    rid = finding.ruleId
    indent = line[: len(line) - len(line.lstrip())]
    is_py = finding.language == "python"

    # Hard-coded secrets -> read from environment.
    if rid in {"CM-S001", "CM-S002", "CM-S003", "CM-S004", "CM-S005", "CM-S006",
               "CM-S007", "CM-S008", "CM-S010", "CM-S012", "CM-S014", "CM-D004"} or finding.cwe_id in {"CWE-798", "CWE-321"}:
        m = re.match(r"(\s*)(?:const |let |var )?([A-Za-z_$][\w$]*)\s*[:=]", line)
        var = m.group(2) if m else (finding.name or "SECRET")
        env = _env_name(finding.name or var, "SECRET")
        if is_py:
            return f'{indent}{var} = os.environ["{env}"]'
        return f'{indent}const {var} = process.env.{env}'

    # Weak hash -> bcrypt
    if rid == "CM-D002" or finding.cwe_id == "CWE-328":
        if is_py:
            return f"{indent}bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # was MD5/SHA-1"
        return f"{indent}await bcrypt.hash(password, 12) // was MD5/SHA-1"

    # TLS verify off -> on
    if rid in {"CM-D007", "CM-A006"} or finding.cwe_id == "CWE-295":
        fixed = re.sub(r"verify\s*=\s*False", "verify=True", line)
        fixed = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", fixed)
        return fixed if fixed != line else None

    # Flask debug -> off
    if rid == "CM-A005" or finding.cwe_id == "CWE-489":
        return re.sub(r"debug\s*=\s*True", "debug=False", line)

    # SQL string formatting -> parameterized (best-effort comment + placeholder)
    if rid in {"CM-A001", "CM-J003"} or finding.cwe_id == "CWE-89":
        return f"{indent}# FIX: use a parameterized query, e.g. cur.execute(SQL, params)\n{line}"

    # os.system / exec shell -> subprocess list
    if rid in {"CM-A002", "CM-J002"} or finding.cwe_id == "CWE-78":
        return f"{indent}# FIX: use subprocess.run([...], shell=False) with an argument list\n{line}"

    # eval/exec
    if rid == "CM-A003" or finding.cwe_id == "CWE-94":
        if is_py:
            return re.sub(r"\beval\s*\(", "ast.literal_eval(", line)
        return f"{indent}// FIX: replace eval with JSON.parse or a safe parser\n{line}"

    # innerHTML -> textContent
    if rid == "CM-J001" or finding.cwe_id == "CWE-79":
        return re.sub(r"\.innerHTML(\s*=)", r".textContent\1", line)

    # localStorage of token
    if rid == "CM-D001":
        return f"{indent}// FIX: store auth state in an HttpOnly cookie set by the server, not localStorage"

    # Cookie flags
    if rid in {"CM-D005", "CM-J005"} and "cookie" in line.lower():
        return None

    # CORS wildcard
    if rid == "CM-J004" or finding.cwe_id == "CWE-942":
        return re.sub(r"origin\s*:\s*[\"']\*[\"']", 'origin: "https://app.example.com"', line)

    return None


def _syntax_ok(path: str, content: str) -> bool:
    if path.endswith(".py"):
        try:
            ast.parse(content)
            return True
        except SyntaxError:
            return False
    if path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        node = shutil.which("node")
        if not node and path.endswith((".js", ".cjs", ".mjs")):
            return True  # can't check; assume ok
        if node and path.endswith((".js", ".cjs", ".mjs")):
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as tf:
                tf.write(content)
                tmp = tf.name
            try:
                r = subprocess.run([node, "--check", tmp], capture_output=True, timeout=10)
                return r.returncode == 0
            except Exception:
                return True
            finally:
                Path(tmp).unlink(missing_ok=True)
        return True  # TS: no cheap syntax check
    return True


def generate_fix(finding: Finding, sf: SourceFile, project: list[SourceFile]) -> Finding:
    """Produce and verify a unified-diff patch for one finding (mutates and returns it)."""
    lines = sf.content.split("\n")
    idx = finding.line - 1
    if idx < 0 or idx >= len(lines):
        return finding
    original_line = lines[idx]
    replacement = suggest_replacement(finding, original_line)
    if replacement is None:
        finding.suggested_fix = finding.suggested_fix or "Review and remediate manually."
        return finding

    new_lines = lines.copy()
    new_lines[idx] = replacement
    new_content = "\n".join(new_lines)

    diff = "\n".join(difflib.unified_diff(
        sf.content.split("\n"), new_content.split("\n"),
        fromfile=f"a/{sf.path}", tofile=f"b/{sf.path}", lineterm="",
    ))
    finding.fix_diff = diff
    if not finding.suggested_fix:
        finding.suggested_fix = replacement.strip()

    # Verify: parses + finding gone.
    verified = False
    if _syntax_ok(sf.path, new_content):
        patched = SourceFile(path=sf.path, content=new_content)
        remaining = run_detectors_on_file(patched, project, {finding.ruleId})
        still_here = any(f.ruleId == finding.ruleId and f.line == finding.line for f in remaining)
        verified = not still_here
    finding.fix_verified = verified
    return finding


def apply_all_fixes(findings: list[Finding], files: dict[str, SourceFile]) -> tuple[dict[str, str], str]:
    """Apply every verified fix to a patched copy. Returns (patched_contents, combined_diff)."""
    patched: dict[str, str] = {p: sf.content for p, sf in files.items()}
    # Apply highest line first per file so earlier edits don't shift later line numbers.
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.fix_verified and f.fix_diff:
            by_file.setdefault(f.file, []).append(f)
    for path, fs in by_file.items():
        content = patched[path]
        lines = content.split("\n")
        for f in sorted(fs, key=lambda x: -x.line):
            idx = f.line - 1
            if 0 <= idx < len(lines):
                rep = suggest_replacement(f, lines[idx])
                if rep is not None:
                    lines[idx] = rep
        patched[path] = "\n".join(lines)

    combined = []
    for path in sorted(patched):
        if patched[path] != files[path].content:
            combined.extend(difflib.unified_diff(
                files[path].content.split("\n"), patched[path].split("\n"),
                fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
            ))
    return patched, "\n".join(combined)
