#!/usr/bin/env python3
"""Optionally enrich the CWE knowledge base from the official MITRE CWE XML.

The seed KB (``data/cwe_seed.json``, built by ``build_cwe_seed.py``) is self-sufficient and
fully offline. If you place the MITRE CWE XML (e.g. ``cwec_latest.xml`` from
https://cwe.mitre.org/data/downloads.html) next to this script or pass its path, this merges
the official name/description/consequences/mitigation into any matching seed entries and can
append new ones. No network access is performed; the file must already be on disk.

Usage:
    python3 scripts/ingest_cwe.py [path/to/cwec.xml]
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SEED = REPO / "data" / "cwe_seed.json"

_NS = re.compile(r"\{[^}]+\}")


def _tag(elem) -> str:
    return _NS.sub("", elem.tag)


def _text(elem) -> str:
    return " ".join(t.strip() for t in elem.itertext() if t.strip())


def parse_mitre(xml_path: Path) -> dict[str, dict]:
    """Return {CWE-id: {name, description, mitigation, consequences}} from the XML."""
    tree = ET.parse(xml_path)
    out: dict[str, dict] = {}
    for weakness in tree.iter():
        if _tag(weakness) != "Weakness":
            continue
        cid = weakness.get("ID")
        if not cid:
            continue
        entry = {"id": f"CWE-{cid}", "name": weakness.get("Name", ""),
                 "description": "", "mitigation": "", "consequences": ""}
        for child in weakness.iter():
            t = _tag(child)
            if t == "Description" and not entry["description"]:
                entry["description"] = _text(child)[:600]
            elif t == "Phase" or t == "Mitigation":
                if not entry["mitigation"]:
                    entry["mitigation"] = _text(child)[:400]
            elif t == "Consequence" and not entry["consequences"]:
                entry["consequences"] = _text(child)[:400]
        out[entry["id"]] = entry
    return out


def main() -> int:
    candidates = [Path(sys.argv[1])] if len(sys.argv) > 1 else [
        Path(__file__).parent / "cwec_latest.xml",
        REPO / "data" / "cwec_latest.xml",
    ]
    xml_path = next((p for p in candidates if p.exists()), None)
    if xml_path is None:
        print("No MITRE CWE XML found; the seed KB is already complete and offline.")
        print("To enrich it, download cwec_latest.xml and pass its path.")
        return 0

    print(f"Parsing {xml_path} …")
    mitre = parse_mitre(xml_path)
    seed = json.loads(SEED.read_text(encoding="utf-8"))
    by_id = {e["id"]: e for e in seed}

    enriched = 0
    for cid, m in mitre.items():
        if cid in by_id:
            e = by_id[cid]
            if m["description"] and len(m["description"]) > len(e.get("description", "")):
                e["description"] = m["description"]
            if m["mitigation"]:
                e["mitigation"] = e.get("mitigation") or m["mitigation"]
            enriched += 1

    SEED.write_text(json.dumps(seed, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Enriched {enriched} existing entries from MITRE. KB has {len(seed)} CWEs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
