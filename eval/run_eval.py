#!/usr/bin/env python3
"""Precision/recall evaluation of both rule engines on the labeled corpus.

Usage (from the repo root):
    backend/.venv/bin/python eval/run_eval.py              # backend + frontend (if Node is available)
    backend/.venv/bin/python eval/run_eval.py --engine backend

A prediction is a unique (rule id, file, line). It is a true positive if the corpus labels that
line with that rule, otherwise a false positive. Labels with no prediction are false negatives.

Thresholds (documented in eval/README.md). The script exits 1 if any is missed:
  * overall precision >= 0.95 and overall recall >= 0.95, per engine;
  * every rule with labels: precision >= 0.80 and recall >= 0.80, per engine;
  * every catalog rule has at least one positive label (coverage).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(HERE))

from corpus_loader import Corpus, load_corpus, materialize  # noqa: E402
from frontend_runner import frontend_available, run_frontend_scan  # noqa: E402

OVERALL_PRECISION = 0.95
OVERALL_RECALL = 0.95
RULE_PRECISION = 0.80
RULE_RECALL = 0.80


def backend_predictions(corpus: Corpus) -> set[tuple[str, str, int]]:
    from app.models.schemas import SourceFile
    from app.pipeline.detect import run_detectors

    files = [SourceFile(path=p, content=c) for p, c in corpus.files.items()]
    return {(f.ruleId, f.file, f.line) for f in run_detectors(files)}


def frontend_predictions(corpus: Corpus) -> set[tuple[str, str, int]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "corpus"
        materialize(corpus, root)
        result = run_frontend_scan(root)
    preds = set()
    for f in result["findings"]:
        path = f["file"].split("/", 1)[1] if f["file"].startswith("corpus/") else f["file"]
        preds.add((f["ruleId"], path, f["line"]))
    return preds


def score(labels: set, preds: set, rule_ids: list[str]) -> dict:
    per = {}
    for rid in rule_ids:
        lab = {x for x in labels if x[0] == rid}
        pre = {x for x in preds if x[0] == rid}
        tp = len(lab & pre)
        fp = len(pre - lab)
        fn = len(lab - pre)
        per[rid] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else (1.0 if not lab else 0.0),
            "recall": tp / (tp + fn) if tp + fn else 1.0,
            "false_positives": sorted(f"{p}:{ln}" for _r, p, ln in pre - lab),
            "false_negatives": sorted(f"{p}:{ln}" for _r, p, ln in lab - pre),
        }
    tp = sum(v["tp"] for v in per.values())
    fp = sum(v["fp"] for v in per.values())
    fn = sum(v["fn"] for v in per.values())
    unknown = sorted({x[0] for x in preds} - set(rule_ids))
    return {
        "rules": per,
        "overall": {"tp": tp, "fp": fp, "fn": fn,
                    "precision": tp / (tp + fp) if tp + fp else 1.0,
                    "recall": tp / (tp + fn) if tp + fn else 1.0},
        "unknown_rules": unknown,
    }


def check(result: dict, rules_with_labels: set[str]) -> list[str]:
    problems = []
    o = result["overall"]
    if o["precision"] < OVERALL_PRECISION:
        problems.append(f"overall precision {o['precision']:.3f} < {OVERALL_PRECISION}")
    if o["recall"] < OVERALL_RECALL:
        problems.append(f"overall recall {o['recall']:.3f} < {OVERALL_RECALL}")
    for rid, v in result["rules"].items():
        if rid in rules_with_labels and v["precision"] < RULE_PRECISION:
            problems.append(f"{rid} precision {v['precision']:.2f} < {RULE_PRECISION} FP={v['false_positives']}")
        if rid in rules_with_labels and v["recall"] < RULE_RECALL:
            problems.append(f"{rid} recall {v['recall']:.2f} < {RULE_RECALL} FN={v['false_negatives']}")
        if rid not in rules_with_labels and v["fp"]:
            problems.append(f"{rid} has no labels but {v['fp']} prediction(s): {v['false_positives']}")
    return problems


def print_table(name: str, result: dict) -> None:
    print(f"\n== {name} ==")
    print(f"{'rule':<9} {'TP':>3} {'FP':>3} {'FN':>3} {'prec':>6} {'recall':>6}")
    for rid, v in result["rules"].items():
        print(f"{rid:<9} {v['tp']:>3} {v['fp']:>3} {v['fn']:>3} {v['precision']:>6.2f} {v['recall']:>6.2f}")
    o = result["overall"]
    print(f"{'OVERALL':<9} {o['tp']:>3} {o['fp']:>3} {o['fn']:>3} {o['precision']:>6.3f} {o['recall']:>6.3f}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["backend", "frontend", "both"], default="both")
    ap.add_argument("--json", action="store_true", help="print machine-readable results")
    args = ap.parse_args(argv)

    from app.detectors.catalog import load_catalog
    rule_ids = list(load_catalog())
    corpus = load_corpus()
    rules_with_labels = {x[0] for x in corpus.labels}
    problems: list[str] = []
    missing = [r for r in rule_ids if r not in rules_with_labels]
    if missing:
        problems.append(f"catalog rules with no positive corpus sample: {missing}")

    results: dict[str, dict] = {}
    engines = ["backend", "frontend"] if args.engine == "both" else [args.engine]
    for engine in engines:
        if engine == "frontend":
            ok, why = frontend_available()
            if not ok:
                msg = f"frontend engine NOT RUN: {why}"
                if args.engine == "frontend":
                    problems.append(msg)
                print(msg)
                continue
            preds = frontend_predictions(corpus)
        else:
            preds = backend_predictions(corpus)
        res = score(corpus.labels, preds, rule_ids)
        results[engine] = res
        problems += [f"[{engine}] {p}" for p in check(res, rules_with_labels)]
        if res["unknown_rules"]:
            problems.append(f"[{engine}] predictions for rules missing from the catalog: {res['unknown_rules']}")

    if args.json:
        print(json.dumps({"results": results, "problems": problems,
                          "labels": len(corpus.labels), "files": len(corpus.files)}, indent=2))
    else:
        print(f"Corpus: {len(corpus.files)} files, {len(corpus.labels)} labeled positives, {len(rule_ids)} rules")
        for name, res in results.items():
            print_table(name, res)
        print("\nThresholds: overall P/R >= %.2f/%.2f, per-rule P/R >= %.2f/%.2f" %
              (OVERALL_PRECISION, OVERALL_RECALL, RULE_PRECISION, RULE_RECALL))
        if problems:
            print("\nFAILED:")
            for p in problems:
                print(f"  - {p}")
        else:
            print("\nPASSED")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
