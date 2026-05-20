#!/usr/bin/env python3
"""
Vexa benchmark harness — measure precision and recall against a labeled APK corpus.

WHAT THIS DOES
==============
This is the scaffolding that turns "we don't know our FP rate" into "here's the
methodology and here are the numbers." It does NOT do measurement on its own —
you have to provide the labeled APKs and the ground-truth file. What it provides
is the *framework* so the measurement is reproducible and honest.

USAGE
=====
1. Create a corpus directory:

    benchmarks/
        labels.json                   <-- the ground truth (see SCHEMA below)
        apks/
            ovaa.apk                  <-- labeled vulnerable app
            diva.apk                  <-- labeled vulnerable app
            insecure-shop.apk         <-- labeled vulnerable app
            clean-todo.apk            <-- known-clean app
            ...

2. Run the harness:

    python benchmark.py benchmarks/

3. Read the report. It prints, per analyzer:
   - True positives (analyzer flagged a finding that's labeled real)
   - False positives (analyzer flagged a finding that's labeled NOT real)
   - False negatives (a labeled finding the analyzer missed)
   - Precision = TP / (TP + FP)
   - Recall    = TP / (TP + FN)


labels.json SCHEMA
==================
{
  "ovaa.apk": {
    "description": "Oversecured Vulnerable Android Application -- known-vulnerable corpus",
    "expected_findings": [
      {
        "id": "exported-activity",      // matches finding.id (or id prefix)
        "where": "com.oversecured.ovaa.activities.MainActivity",  // optional context match
        "severity": "high",              // optional: must match
        "must_find": true                // if true: missing = false negative
      },
      ...
    ],
    "expected_clean": []                 // analyzer ids that should NEVER flag this APK
  },
  "clean-todo.apk": {
    "description": "Built-from-source todo app, no known issues",
    "expected_findings": [],             // a clean app -> any flag is a false positive
    "expected_clean": ["*"]              // wildcard: NO analyzer should fire
  }
}


SUGGESTED CORPUS (for first measurement run)
============================================
Vulnerable, well-documented:
- OVAA (Oversecured Vulnerable Android App): https://github.com/oversecured/ovaa
- DIVA (Damn Insecure and Vulnerable App): https://github.com/payatu/diva-android
- InsecureShop:              https://github.com/optiv/InsecureShop
- InjuredAndroid (CTF-style): https://github.com/B3nac/InjuredAndroid
- AndroGoat:                 https://github.com/satishpatnayak/AndroGoat

Clean baseline (build from source, target a known stable commit):
- A simple TODO app you wrote
- A "Hello World" Android Studio template
- An open-source app you trust (e.g. an F-Droid app with active maintainers)

You will spend several days writing labels.json carefully. That's what
measurement actually requires. There is no shortcut.


HONEST CAVEATS
==============
- This harness does NOT auto-label APKs. You write the labels yourself, by hand,
  for each app in the corpus. That work is what makes the measurement valid.

- "True positive" requires both Vexa's flag AND your label to agree. If Vexa
  finds a real bug you didn't label, the harness reports it as a false positive
  even though it's actually a true positive. Your label set is the ceiling on
  Vexa's measured precision.

- The output is ONLY as good as your corpus diversity. Measuring against 5 apps
  tells you almost nothing. 20 apps gives you signal. 100+ is what published
  scanners measure against (and Oversecured has tested against thousands).

- The numbers will move as you tune analyzers and as you expand the corpus.
  Re-run after every batch of analyzer changes; commit the JSON output to git
  so you have a history.
"""

import argparse
import json
import os
import sys
import time
import logging
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vexa-bench")


def load_labels(corpus_dir: Path) -> dict:
    """Load labels.json from the corpus directory."""
    labels_path = corpus_dir / "labels.json"
    if not labels_path.exists():
        log.error("labels.json not found at %s", labels_path)
        log.error("See the docstring at the top of benchmark.py for the schema.")
        sys.exit(1)
    with labels_path.open() as f:
        return json.load(f)


def scan_one_apk(vexa_module, apk_path: Path, run_taint: bool = True) -> dict:
    """Run Vexa's scan pipeline against one APK and return its findings list."""
    log.info("Scanning %s ...", apk_path.name)
    t0 = time.time()
    try:
        report = vexa_module.scan_apk_static(str(apk_path))
        elapsed = time.time() - t0
        log.info("  done in %.1fs, %d findings", elapsed, len(report.get("findings", [])))
        return report
    except Exception as e:
        log.exception("Scan failed for %s: %s", apk_path, e)
        return {"findings": []}


def match_finding(actual: dict, expected: dict) -> bool:
    """Decide if an actual Vexa finding matches an expected (labeled) finding.

    Match is structural: the actual finding's id must equal or have-as-prefix the
    expected id; if expected sets `where` or `severity`, those must also match.
    """
    actual_id = (actual.get("id") or "").lower()
    expected_id = expected.get("id", "").lower()
    if not expected_id:
        return False
    # Allow id-prefix matching: "secret" matches "secret-aws-key-1"
    if actual_id != expected_id and not actual_id.startswith(expected_id + "-"):
        return False
    # If expected provides a 'where' (class / method / file), require it appears in evidence
    where = expected.get("where", "")
    if where:
        evidence = (actual.get("evidence") or "")
        if where.lower() not in evidence.lower():
            return False
    # Severity match
    if expected.get("severity") and actual.get("severity") != expected["severity"]:
        return False
    return True


def evaluate(corpus_dir: Path, labels: dict) -> dict:
    """Run Vexa across every labeled APK and compute precision/recall.

    Returns a results dict keyed by analyzer source-id, with per-analyzer counts.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        import vexa
    except ImportError:
        log.error("Could not import vexa.py -- is it in the same directory as benchmark.py?")
        sys.exit(1)

    apks_dir = corpus_dir / "apks"
    if not apks_dir.is_dir():
        log.error("No apks/ directory in %s", corpus_dir)
        sys.exit(1)

    # Per-analyzer stats:
    # tp: true positives (flagged + labeled real)
    # fp: false positives (flagged + labeled NOT real)
    # fn: false negatives (labeled real but NOT flagged)
    # by_source: same broken down by analyzer source (vexa, vexa-taint, plugin, ...)
    stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0,
                                  "tp_examples": [], "fp_examples": [], "fn_examples": []})

    apks_seen = 0
    apks_matched = 0
    total_findings = 0

    for apk_filename, label_entry in labels.items():
        apk_path = apks_dir / apk_filename
        if not apk_path.exists():
            log.warning("APK in labels but not on disk: %s", apk_filename)
            continue
        apks_seen += 1

        report = scan_one_apk(vexa, apk_path)
        findings = report.get("findings", [])
        total_findings += len(findings)

        expected_findings = label_entry.get("expected_findings", [])
        expected_clean = label_entry.get("expected_clean", [])

        # --- Match each expected finding against actual findings ---
        for exp in expected_findings:
            analyzer = exp.get("analyzer", "any")
            matched = any(match_finding(actual, exp) for actual in findings)
            key = exp.get("id", "?")
            if matched:
                stats[analyzer]["tp"] += 1
                stats[analyzer]["tp_examples"].append(f"{apk_filename}: {key}")
            elif exp.get("must_find", True):
                stats[analyzer]["fn"] += 1
                stats[analyzer]["fn_examples"].append(f"{apk_filename}: {key}")
        if expected_findings:
            apks_matched += 1

        # --- For each actual finding, see if it matches an expected one ---
        for actual in findings:
            actual_id = actual.get("id", "")
            actual_source = actual.get("source", "vexa")
            matched_any = any(match_finding(actual, exp) for exp in expected_findings)
            if matched_any:
                continue  # already counted as TP above
            # Wildcard "expected_clean": ANY flag on this APK is a FP
            if "*" in expected_clean:
                stats[actual_source]["fp"] += 1
                stats[actual_source]["fp_examples"].append(f"{apk_filename}: {actual_id}")
                continue
            # Specific clean list
            if actual_id in expected_clean or any(actual_id.startswith(c + "-") for c in expected_clean):
                stats[actual_source]["fp"] += 1
                stats[actual_source]["fp_examples"].append(f"{apk_filename}: {actual_id}")
                continue
            # Otherwise: undecidable -- the label set didn't say either way.
            # Counted as "unknown" below.

    return {
        "corpus_dir": str(corpus_dir),
        "apks_seen": apks_seen,
        "apks_matched": apks_matched,
        "total_findings": total_findings,
        "per_analyzer": dict(stats),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def print_report(results: dict, json_out: bool = False):
    if json_out:
        print(json.dumps(results, indent=2))
        return

    print()
    print("=" * 70)
    print("Vexa benchmark report")
    print("=" * 70)
    print(f"Corpus:           {results['corpus_dir']}")
    print(f"APKs scanned:     {results['apks_seen']}")
    print(f"Total findings:   {results['total_findings']}")
    print(f"Generated:        {results['timestamp']}")
    print()

    per_analyzer = results["per_analyzer"]
    if not per_analyzer:
        print("(no analyzer-level data -- check your labels.json schema)")
        return

    # Print per-analyzer table
    print(f"{'Analyzer':<35} {'TP':>5} {'FP':>5} {'FN':>5} {'Precision':>10} {'Recall':>8}")
    print("-" * 75)
    overall_tp = overall_fp = overall_fn = 0
    for analyzer in sorted(per_analyzer.keys()):
        s = per_analyzer[analyzer]
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        overall_tp += tp; overall_fp += fp; overall_fn += fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        prec_str = f"{precision:.1%}" if precision == precision else "—"
        rec_str = f"{recall:.1%}" if recall == recall else "—"
        print(f"{analyzer:<35} {tp:>5} {fp:>5} {fn:>5} {prec_str:>10} {rec_str:>8}")

    print("-" * 75)
    overall_prec = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else float("nan")
    overall_rec = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else float("nan")
    overall_fp_rate = overall_fp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else float("nan")
    print(f"{'OVERALL':<35} {overall_tp:>5} {overall_fp:>5} {overall_fn:>5} "
          f"{overall_prec:>10.1%} {overall_rec:>8.1%}")
    print()
    print(f"Overall false-positive rate: {overall_fp_rate:.1%}")
    print(f"  (FP / (TP + FP) -- the fraction of flagged findings that were wrong)")
    print()


def main():
    parser = argparse.ArgumentParser(description="Vexa benchmark harness.")
    parser.add_argument("corpus_dir", type=Path, help="Path to corpus directory containing labels.json + apks/")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of human-readable report")
    parser.add_argument("--save", type=Path, help="Save results to a JSON file for trend tracking")
    args = parser.parse_args()

    if not args.corpus_dir.is_dir():
        log.error("Corpus directory not found: %s", args.corpus_dir)
        sys.exit(1)

    labels = load_labels(args.corpus_dir)
    log.info("Loaded labels for %d APK(s)", len(labels))

    results = evaluate(args.corpus_dir, labels)
    print_report(results, json_out=args.json)

    if args.save:
        with args.save.open("w") as f:
            json.dump(results, f, indent=2)
        log.info("Results saved to %s", args.save)


if __name__ == "__main__":
    main()
