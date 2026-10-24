"""Pydantic v2 models — the API contract.

The frontend (``frontend/src/lib/types.ts``) defines ``Finding`` / ``ScanReport`` /
``Severity`` / ``Category``. We mirror those names and add the richer backend-only
fields (CWE grounding, validation trace, fix diff) as optional extensions so the
existing frontend keeps working while new UI can use the extras.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["secrets", "pii", "storage", "code", "injection", "auth", "misc"]
Language = Literal[
    "javascript", "typescript", "python", "java", "go", "php",
    "env", "json", "yaml", "toml", "ini", "sql", "shell", "text",
]
FindingSource = Literal["detector", "llm", "both"]


class SourceFile(BaseModel):
    path: str
    content: str


class ValidationTrace(BaseModel):
    """Explainable record of every anti-hallucination check a finding passed."""
    evidence_in_source: bool = False
    cwe_known: bool = False
    cwe_pattern_match: bool = False
    confirmed_by_detector: bool = False
    needs_review: bool = False
    notes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    # --- Fields shared with the frontend Finding shape ---
    id: str
    ruleId: str = ""
    category: Category = "misc"
    severity: Severity = "info"
    file: str
    language: Language = "text"
    line: int = 1
    column: int = 1
    endLine: int = 1
    endColumn: int = 1
    # Absolute character offsets into the in-memory file (frontend viewer uses these).
    start: int = 0
    end: int = 0
    sensitive: bool = False
    maskedValue: str = ""
    snippet: str = ""
    confidence: float = 0.0
    note: Optional[str] = None
    name: Optional[str] = None

    # --- Backend extensions (CWE grounding, scoring, validation, fix) ---
    cwe_id: Optional[str] = None
    title: str = ""
    evidence_snippet: str = ""
    explanation: str = ""
    attack_scenario: str = ""
    suggested_fix: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    fix_diff: str = ""
    fix_verified: bool = False
    fix_note: str = ""
    # Local AI enrichment: "none" (AI off), "ai" (model explanation/fix used) or "ai_fallback"
    # (model output rejected; the rule's built-in explanation and fix are shown).
    ai_status: Literal["none", "ai", "ai_fallback"] = "none"
    ai_detail: str = ""
    source: FindingSource = "detector"
    severity_score: float = 0.0
    severity_reason: str = ""
    validation: ValidationTrace = Field(default_factory=ValidationTrace)


class FileSummary(BaseModel):
    path: str
    language: Language
    lines: int
    bytes: int


class SkippedFile(BaseModel):
    path: str
    reason: Literal["too-large", "unsupported", "binary", "ignored-dir", "test-or-generated"]


class PrivacyAttestation(BaseModel):
    data_leaves_machine: bool
    analysis_location: str = "local-machine"
    model: str
    seed: int
    temperature: float
    top_k: int
    top_p: float
    llm_mock: bool
    endpoints_checked: list[str] = Field(default_factory=list)
    ai_enabled: bool = False
    model_digest: Optional[str] = None
    prompt_version: Optional[str] = None


class ScanReport(BaseModel):
    id: str
    name: str
    createdAt: int = 0
    durationMs: int = 0
    files: list[FileSummary] = Field(default_factory=list)
    skipped: list[SkippedFile] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    rulesRun: int = 0
    seedId: Optional[str] = None

    # Backend extensions
    security_score: int = 100
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    executive_summary: str = ""
    privacy: Optional[PrivacyAttestation] = None
    chaos_mode: Optional["ChaosModeResult"] = None


class ChaosModeResult(BaseModel):
    """Result of the mutation / self-test pass."""
    injected: int = 0
    detected: int = 0
    detection_rate: float = 0.0
    details: list[dict[str, Any]] = Field(default_factory=list)


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"


class ScanRecord(BaseModel):
    id: str
    status: ScanStatus = ScanStatus.queued
    stage: str = "queued"
    progress: float = 0.0
    error: Optional[str] = None
    report: Optional[ScanReport] = None


# --- Request bodies ---

class ScanRequest(BaseModel):
    name: str = "scan"
    code: Optional[str] = None
    filename: Optional[str] = None
    files: list[SourceFile] = Field(default_factory=list)
    path: Optional[str] = None
    enabled_rule_ids: Optional[list[str]] = None
    use_llm: bool = True
    chaos_mode: bool = False
    # Scan tests/fixtures/vendor/minified/lock files too (skipped by default to cut false positives).
    include_test_paths: bool = False


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""


ScanReport.model_rebuild()
