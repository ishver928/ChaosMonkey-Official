"""LLM ANALYSIS stage: chunk code, ground it with retrieved CWEs, get JSON findings.

Code is split into overlapping line windows. For each chunk we retrieve the top-k CWEs,
build a strict JSON-output prompt that includes the chunk, the CWE context, and detector
hints, then ask the local model (or the deterministic mock). The model's line numbers are
resolved back to absolute file lines. Validation happens later in ``validate.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kb.store import KnowledgeBase
from ..llm.client import analyze_chunk
from ..models.schemas import Finding, SourceFile

CHUNK_LINES = 80
OVERLAP = 20


@dataclass
class Chunk:
    start_line: int  # 1-based line where the chunk begins
    text: str


def chunk_file(content: str, size: int = CHUNK_LINES, overlap: int = OVERLAP) -> list[Chunk]:
    lines = content.split("\n")
    if len(lines) <= size:
        return [Chunk(1, content)]
    chunks = []
    step = max(1, size - overlap)
    i = 0
    while i < len(lines):
        window = lines[i:i + size]
        chunks.append(Chunk(i + 1, "\n".join(window)))
        if i + size >= len(lines):
            break
        i += step
    return chunks


def build_prompt(file: str, start_line: int, code: str, cwe_context: list[dict], hints: list[str]) -> str:
    ctx_lines = []
    for c in cwe_context:
        ex = c.get("examples", {})
        vuln = ex.get("python", {}).get("vulnerable") or ex.get("javascript", {}).get("vulnerable") or ""
        ctx_lines.append(f"- {c['id']} {c['name']}: {c['description']} Example: {vuln}")
    ctx_block = "\n".join(ctx_lines) if ctx_lines else "(none)"
    hint_block = "\n".join(f"- {h}" for h in hints) if hints else "(none)"
    numbered = "\n".join(f"{start_line + i}: {ln}" for i, ln in enumerate(code.split("\n")))
    return f"""You are a deterministic application-security analyzer running locally. Analyze the code and report real vulnerabilities only. Never invent code that is not present.

Relevant CWE references:
{ctx_block}

Deterministic detector hints already found in this file:
{hint_block}

Return STRICT JSON with this exact schema and nothing else:
{{"findings": [{{"cwe_id": "CWE-###", "title": "...", "line_start": <int>, "line_end": <int>, "evidence_snippet": "<verbatim line from the code>", "explanation": "...", "attack_scenario": "...", "confidence": <0..1>, "suggested_fix": "..."}}]}}

Rules:
- evidence_snippet MUST be copied verbatim from a line below.
- Only use cwe_id values from the references above.
- If there are no issues, return {{"findings": []}}.

File: {file}
Code (line: content):
{numbered}
"""


def llm_findings_for_file(
    sf: SourceFile,
    kb: KnowledgeBase,
    detector_hints: list[str],
    top_k: int = 4,
) -> list[dict]:
    """Return raw candidate finding dicts (unvalidated) with absolute line numbers."""
    out: list[dict] = []
    for chunk in chunk_file(sf.content):
        cwes = kb.retrieve(chunk.text, top_k=top_k)
        cwe_context = [
            {"id": e.id, "name": e.name, "description": e.description, "examples": e.examples}
            for e in cwes
        ]
        prompt = build_prompt(sf.path, chunk.start_line, chunk.text, cwe_context, detector_hints)
        result = analyze_chunk(prompt, chunk.text, cwe_context)
        for raw in result.get("findings", []):
            if not isinstance(raw, dict):
                continue
            raw = dict(raw)
            raw["file"] = sf.path
            # Line numbers from the model are only a hint; the validator resolves the
            # true line by locating evidence_snippet in the file. Record the chunk origin.
            raw["_chunk_start"] = chunk.start_line
            out.append(raw)
    return out
