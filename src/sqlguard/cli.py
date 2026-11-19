from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .attacks import ablation, render_ablation
from .db import build_database
from .guard import GuardViolation, Policy, validate

DEFAULT_DB = Path("data/consulting.db")


def _client(backend: str, effort: str | None):
    if backend == "api":
        import anthropic

        return anthropic.Anthropic()
    from .claude_code import ClaudeCodeClient

    return ClaudeCodeClient(effort=effort)


def _save(out: Path, name: str, data: dict, report: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out / f"{name}.md").write_text(report, encoding="utf-8")
    print(report)
    print(f"Wrote {out / (name + '.json')} and {out / (name + '.md')}")


def main(argv: list[str] | None = None) -> int:
    from .llm import DEFAULT_MODEL

    parser = argparse.ArgumentParser(prog="sqlguard")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build-db", help="Create the synthetic consulting database")
    check = sub.add_parser("check", help="Run a SQL string through the parser guardrail")
    check.add_argument("sql")
    sub.add_parser("attacks", help="Run the SQL attack suite against every combination of guardrail layers (no model)")
    regrade = sub.add_parser("regrade-redteam", help="Re-score a saved red-team run by replaying its SQL, without calling any model")
    regrade.add_argument("results", type=Path)
    sub.add_parser("differencing", help="Show a differencing attack on salary statistics, with and without the audit layer (no model)")

    def model_args(p):
        p.add_argument("--model", default=DEFAULT_MODEL)
        p.add_argument("--backend", choices=["claude-code", "api"], default="claude-code",
                       help="claude-code (default) uses your Claude Code login, no API key. api uses ANTHROPIC_API_KEY and bills that key.")
        p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
        p.add_argument("--workers", type=int, default=4)
        p.add_argument("--out", type=Path, default=Path("results"))

    ask = sub.add_parser("ask", help="Ask the database a question in plain English")
    ask.add_argument("question")
    ask.add_argument("--no-guardrails", action="store_true", help="Demonstration only: run the model's SQL with every layer off, on a throwaway copy")
    model_args(ask)
    acc = sub.add_parser("eval-accuracy", help="Score the model's SQL against reference answers")
    model_args(acc)
    red = sub.add_parser("redteam", help="Send hostile questions through the model under four prompt and guardrail configurations")
    red.add_argument("--only", nargs="+", help="Scenario ids to run")
    red.add_argument("--configs", nargs="+")
    model_args(red)

    args = parser.parse_args(argv)
    if args.command == "build-db":
        args.db.parent.mkdir(parents=True, exist_ok=True)
        print(f"Built {build_database(args.db)}")
        return 0
    if not args.db.exists():
        parser.error(f"{args.db} does not exist; run `sqlguard build-db` first")
    if args.command == "check":
        try:
            print("allowed:", validate(args.sql, Policy.for_database(args.db)).sql)
        except GuardViolation as violation:
            print(f"blocked ({violation.code}): {violation}")
            return 1
        return 0
    if args.command == "attacks":
        print(render_ablation(ablation(args.db)))
        return 0
    if args.command == "regrade-redteam":
        from .redteam import regrade_redteam, render_redteam

        data = json.loads(args.results.read_text(encoding="utf-8"))
        backup = args.results.with_name("redteam.before-regrade.json")
        if not backup.exists():
            backup.write_text(args.results.read_text(encoding="utf-8"), encoding="utf-8")
        _save(args.results.parent, "redteam", regrade_redteam(data, args.db), render_redteam(data))
        return 0
    if args.command == "differencing":
        from .privacy import differencing_attack, render

        policy = Policy.for_database(args.db)
        print(render(differencing_attack(args.db, policy, use_audit=False), differencing_attack(args.db, policy, use_audit=True)))
        return 0

    client = _client(args.backend, args.effort)
    print(f"Backend: {args.backend}", file=sys.stderr, flush=True)
    if args.command == "ask":
        import shutil
        import tempfile

        from .llm import run_agent, schema_text
        from .sandbox import AuditLog, Layers

        policy = Policy.for_database(args.db)
        layers = Layers.none() if args.no_guardrails else Layers()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "copy.db"
            shutil.copy(args.db, target)
            run = run_agent(client, args.model, target, policy, layers, args.question, schema=schema_text(args.db, policy, "filtered"), safety_prompt=not args.no_guardrails, audit=AuditLog())
        for a in run.attempts:
            print(f"[{a.status}{' ' + a.code if a.code else ''}] {a.sql}")
        print("\n" + (run.answer if run.finished else "(no final answer within the step limit)"))
        return 0
    if args.command == "eval-accuracy":
        from .evaluation import render_accuracy, run_accuracy

        data = run_accuracy(client, args.model, args.db, workers=args.workers)
        _save(args.out, "accuracy", data, render_accuracy(data))
        return 0
    from .redteam import SCENARIOS, render_redteam, run_redteam

    scenarios = [s for s in SCENARIOS if not args.only or s.id in args.only]
    data = run_redteam(client, args.model, args.db, scenarios, args.configs, args.workers)
    _save(args.out, "redteam", data, render_redteam(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
