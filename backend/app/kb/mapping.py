"""Mappings between detector rule ids and CWEs, plus a pattern-to-CWE plausibility map.

The validator uses ``cwe_plausible_for_code`` to reject an LLM finding whose CWE does
not match any recognisable pattern in the cited code.
"""

from __future__ import annotations

import re

# Detector/LLM rule id -> CWE id. Built-in CM-* rules reuse the frontend ids.
RULE_TO_CWE: dict[str, str] = {
    # Secrets
    "CM-S001": "CWE-798", "CM-S002": "CWE-798", "CM-S003": "CWE-798", "CM-S004": "CWE-798",
    "CM-S005": "CWE-798", "CM-S006": "CWE-798", "CM-S007": "CWE-798", "CM-S008": "CWE-798",
    "CM-S009": "CWE-321", "CM-S010": "CWE-798", "CM-S011": "CWE-798", "CM-S012": "CWE-798",
    "CM-S013": "CWE-312", "CM-S014": "CWE-798",
    # PII
    "CM-P001": "CWE-200", "CM-P002": "CWE-200", "CM-P003": "CWE-200", "CM-P004": "CWE-200",
    "CM-P005": "CWE-200", "CM-P006": "CWE-532", "CM-P007": "CWE-200",
    # Storage
    "CM-D001": "CWE-312", "CM-D002": "CWE-328", "CM-D003": "CWE-312", "CM-D004": "CWE-321",
    "CM-D005": "CWE-1004", "CM-D006": "CWE-312", "CM-D007": "CWE-295", "CM-D008": "CWE-312",
    # Python AST
    "CM-A001": "CWE-89", "CM-A002": "CWE-78", "CM-A003": "CWE-94", "CM-A004": "CWE-502",
    "CM-A005": "CWE-489", "CM-A006": "CWE-295", "CM-A007": "CWE-22",
    # JS
    "CM-J001": "CWE-79", "CM-J002": "CWE-78", "CM-J003": "CWE-89", "CM-J004": "CWE-942",
    "CM-J005": "CWE-347",
}

# CWE -> regex that should appear in code for the CWE to be plausible there.
CWE_PATTERNS: dict[str, re.Pattern[str]] = {
    "CWE-89": re.compile(r"execute|query|select|insert|update|delete|cursor|sql", re.I),
    "CWE-79": re.compile(r"innerhtml|dangerouslysetinnerhtml|document\.write|render", re.I),
    "CWE-78": re.compile(r"system|subprocess|popen|exec|spawn|child_process|shell", re.I),
    "CWE-22": re.compile(r"open|read|path|file|join|download|sendfile", re.I),
    "CWE-798": re.compile(r"key|secret|token|password|credential|api", re.I),
    "CWE-259": re.compile(r"password|passwd|pwd", re.I),
    "CWE-321": re.compile(r"secret|key|sign|jwt|hmac|private", re.I),
    "CWE-327": re.compile(r"des|rc4|md5|sha1|cipher|crypt", re.I),
    "CWE-328": re.compile(r"md5|sha1|hash", re.I),
    "CWE-502": re.compile(r"pickle|yaml|load|marshal|deserial", re.I),
    "CWE-918": re.compile(r"request|fetch|urlopen|url|axios|get", re.I),
    "CWE-352": re.compile(r"csrf|token|form|post|cookie", re.I),
    "CWE-287": re.compile(r"login|auth|token|verify|session|password", re.I),
    "CWE-306": re.compile(r"route|admin|endpoint|app\.(get|post|put|delete)", re.I),
    "CWE-862": re.compile(r"admin|role|authorize|owner|permission", re.I),
    "CWE-639": re.compile(r"id|param|findby|userid|object", re.I),
    "CWE-200": re.compile(r"email|ssn|phone|card|profile|user|response|json|return", re.I),
    "CWE-532": re.compile(r"log|print|console|logger|logging", re.I),
    "CWE-312": re.compile(r"localstorage|store|save|write|file|password|secret|plain", re.I),
    "CWE-311": re.compile(r"http|ssl|tls|verify|secure|cookie", re.I),
    "CWE-434": re.compile(r"upload|file|save|multipart|filename", re.I),
    "CWE-601": re.compile(r"redirect|location|url|next|return", re.I),
    "CWE-611": re.compile(r"xml|etree|parse|entity|dtd|lxml", re.I),
    "CWE-94": re.compile(r"eval|exec|compile|function", re.I),
    "CWE-117": re.compile(r"log|logger|print|console", re.I),
    "CWE-209": re.compile(r"except|catch|error|traceback|stack|debug", re.I),
    "CWE-295": re.compile(r"verify|rejectunauthorized|ssl|insecure|tls", re.I),
    "CWE-330": re.compile(r"random|rand|token|uuid", re.I),
    "CWE-489": re.compile(r"debug|run|flask|development", re.I),
    "CWE-1004": re.compile(r"cookie|httponly|samesite|secure", re.I),
    "CWE-942": re.compile(r"cors|origin|access-control|credentials", re.I),
    "CWE-347": re.compile(r"jwt|decode|verify|alg|signature", re.I),
}


def cwe_plausible_for_code(cwe_id: str, code: str) -> bool:
    """True if the CWE's characteristic pattern appears in the cited code."""
    rx = CWE_PATTERNS.get(cwe_id)
    if rx is None:
        return False
    return bool(rx.search(code))


def cwe_for_rule(rule_id: str) -> str | None:
    return RULE_TO_CWE.get(rule_id)
