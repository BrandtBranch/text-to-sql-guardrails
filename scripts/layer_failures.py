"""What happens when a guardrail layer fails? Replay the attacks that work with no protection, with one or two layers switched off.

    python scripts/layer_failures.py --out results/layer-failures

No model is involved. The baseline is the set of attacks that work with every layer off. Three overload attacks sit near the 2.5 second
line that counts them as working, so the baseline can be 49 to 51 depending on how busy the machine is. The script retries until it
sees all 51, and says so if it never does.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

from sqlguard.attacks import ATTACKS, read_truth, run_attack
from sqlguard.db import build_database
from sqlguard.guard import Policy
from sqlguard.sandbox import Layers

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "consulting.db"
NAMES = ["parser", "readonly", "authorizer", "limits"]
LABEL = {"parser": "query checker", "readonly": "read-only mode", "authorizer": "permission check", "limits": "time and row limit"}


def layers(on: set[str]) -> Layers:
    return Layers(**{n: n in on for n in NAMES}, audit=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "results" / "layer-failures"))
    parser.add_argument("--attempts", type=int, default=10)
    args = parser.parse_args()
    if not DB.exists():
        build_database(DB)
    policy, truth = Policy.for_database(DB), read_truth(DB)
    by_name = {a.name: a for a in ATTACKS}

    real: list[str] = []
    for attempt in range(1, args.attempts + 1):
        real = [a.name for a in ATTACKS if run_attack(a, DB, policy, layers(set()), truth)[0]]
        print(f"attempt {attempt}: {len(real)} of {len(ATTACKS)} attacks work with no protection", flush=True)
        if len(real) == 51:
            break

    def through(on: set[str]) -> list[str]:
        return [n for n in real if run_attack(by_name[n], DB, policy, layers(on), truth)[0]]

    full = set(NAMES)
    result = {"baseline_working": len(real), "all_layers_on": len(through(full)), "one_layer_fails": {}, "two_layers_fail": {}, "one_layer_only": {}}
    for n in NAMES:
        result["one_layer_fails"][n] = through(full - {n})
        result["one_layer_only"][n] = through({n})
    for pair in itertools.combinations(NAMES, 2):
        result["two_layers_fail"]["+".join(pair)] = through(full - set(pair))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "layer_failures.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    lines = ["# What happens when a layer fails", "",
             f"Attacks that work with no protection in this run: {len(real)} of {len(ATTACKS)}. With all four layers on, {result['all_layers_on']} get through.", "",
             "| Layer that fails (the other three stay on) | Attacks that get through |", "|---|---|"]
    lines += [f"| {LABEL[n]} | {len(v)} |" for n, v in result["one_layer_fails"].items()]
    lines += ["", "| Two layers fail together | Attacks that get through |", "|---|---|"]
    lines += [f"| {' + '.join(LABEL[x] for x in k.split('+'))} | {len(v)} |" for k, v in result["two_layers_fail"].items()]
    lines += ["", "| Only this layer is on | Attacks that get through |", "|---|---|"]
    lines += [f"| {LABEL[n]} | {len(v)} |" for n, v in result["one_layer_only"].items()]
    if len(real) != 51:
        lines += ["", f"Note: the baseline was {len(real)}, not 51, because of the timing-sensitive overload attacks."]
    (out / "layer_failures.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
