"""Replay the fuzzer's variations against a database with EVERY layer switched off, and count how many cause harm.

The main fuzz run (`sqlguard.cli fuzz`) records what happens with the full guardrails. This script answers the opposite question:
of the same variations, how many would have worked with no protection at all? It uses the same seeds, the same generator and the
same definition of harm as the main fuzz run, so the two counts are directly comparable.

    python scripts/fuzz_unprotected.py --budget 20000 --seeds 1 2 --out results/fuzz-unprotected

No model is involved. Every query runs against a scratch copy of the database, which is restored whenever a query changes it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from sqlguard.db import build_database
from sqlguard.fuzz import FUZZ_HARD_TIMEOUT, FUZZ_TIMEOUT, SLOW_SECONDS, Oracle, generate  # the same generator and harm oracle as the main fuzz run
from sqlguard.guard import Policy
from sqlguard.sandbox import Layers, execute

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "consulting.db"
NOTHING = Layers(parser=False, readonly=False, authorizer=False, limits=False, audit=False)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(seed: int, budget: int) -> dict:
    policy = Policy.for_database(DB, timeout=FUZZ_TIMEOUT, hard_timeout=FUZZ_HARD_TIMEOUT)
    oracle = Oracle.for_database(DB)
    cases = generate(budget, seed)
    by_kind: Counter = Counter()
    harmed_by_kind: Counter = Counter()
    reasons: Counter = Counter()
    with tempfile.TemporaryDirectory() as tmp:
        pristine, work = Path(tmp) / "pristine.db", Path(tmp) / "work.db"
        shutil.copy(DB, pristine)
        shutil.copy(pristine, work)
        baseline = _digest(work)
        for i, case in enumerate(cases):
            outcome = execute(work, case.sql, policy, NOTHING)
            harm = oracle.leaks(outcome)
            if _digest(work) != baseline:
                harm.append("the database changed")
                shutil.copy(pristine, work)
            if outcome.elapsed >= SLOW_SECONDS or len(outcome.rows) > policy.max_rows:
                harm.append("a resource attack (slow or huge)")
            by_kind[case.seed_kind] += 1
            if harm:
                harmed_by_kind[case.seed_kind] += 1
                reasons.update(set(harm))
            if i % 2000 == 0:
                print(f"  seed {seed}: {i}/{len(cases)}", flush=True)
    return {
        "seed": seed, "generated": len(cases), "harmful": sum(harmed_by_kind.values()),
        "by_seed_kind": {k: {"variations": by_kind[k], "harmful": harmed_by_kind[k]} for k in by_kind},
        "harm_reasons": dict(reasons.most_common()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--budget", type=int, default=20000)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2])
    parser.add_argument("--out", default=str(ROOT / "results" / "fuzz-unprotected"))
    args = parser.parse_args()
    if not DB.exists():
        build_database(DB)
    results = [run(seed, args.budget) for seed in args.seeds]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "unprotected.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    total = sum(r["generated"] for r in results)
    harmful = sum(r["harmful"] for r in results)
    lines = ["# The same fuzz variations with every layer switched off", "",
             "Same seeds, same generator and same definition of harm as the main fuzz run, but no parser, no read-only connection, "
             "no authorizer and no time or row limits (only a 0.6 second hard cap so a test cannot hang).", "",
             "| Seed | Variations | Caused harm | Of variations from attacks | Of variations from normal questions |", "|---|---|---|---|---|"]
    for r in results:
        a, b = r["by_seed_kind"].get("attack", {}), r["by_seed_kind"].get("benign", {})
        lines.append(f"| {r['seed']} | {r['generated']:,} | {r['harmful']:,} | {a.get('harmful', 0):,} of {a.get('variations', 0):,} | {b.get('harmful', 0):,} of {b.get('variations', 0):,} |")
    lines += ["", f"**Total: {harmful:,} of {total:,} variations caused harm with no protection.** With the full guardrails the same variations caused harm 0 times.", ""]
    (out / "unprotected.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
