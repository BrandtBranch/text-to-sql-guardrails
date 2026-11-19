"""Accuracy test: does the model write correct SQL, and do the guardrails get in the way?

Each question is answered once. The generated SQL is run twice, unguarded on a throwaway copy and guarded on the real
database, and both results are compared with the reference answer. The gap between the two is the cost of the guardrails.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .guard import Policy
from .llm import generate_sql, schema_text
from .questions import QUESTIONS, Question, same_result
from .sandbox import Layers, execute


@dataclass
class QuestionResult:
    id: str
    level: str
    question: str
    sql: str
    unguarded: str  # correct | wrong | error
    guarded: str  # correct | wrong | blocked | error
    block_code: str | None = None
    detail: str = ""


def _grade(outcome, gold_rows, ordered: bool) -> str:
    if outcome.status == "blocked":
        return "blocked"
    if outcome.status != "ok":
        return "error"
    return "correct" if same_result(gold_rows, outcome.rows, ordered) else "wrong"


def evaluate_question(client: Any, model: str, db: Path, policy: Policy, schema: str, q: Question) -> QuestionResult:
    try:
        sql = generate_sql(client, model, schema, q.text)
    except Exception as exc:  # one failed call should not lose the rest of the run
        return QuestionResult(q.id, q.level, q.text, "", "error", "error", detail=f"{type(exc).__name__}: {exc}"[:200])
    gold = execute(db, q.gold_sql, policy, Layers.none()).rows
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "copy.db"
        shutil.copy(db, copy)
        unguarded = execute(copy, sql, policy, Layers.none())
    guarded = execute(db, sql, policy, Layers())
    return QuestionResult(q.id, q.level, q.text, sql, _grade(unguarded, gold, q.ordered), _grade(guarded, gold, q.ordered),
                          guarded.code if guarded.status != "ok" else None, guarded.detail[:200])


def run_accuracy(client: Any, model: str, db: Path, questions: list[Question] | None = None, workers: int = 4) -> dict[str, Any]:
    policy = Policy.for_database(db)
    schema = schema_text(db, policy, "filtered")
    questions = questions or QUESTIONS
    done, lock = [0], threading.Lock()

    def one(q: Question) -> QuestionResult:
        result = evaluate_question(client, model, db, policy, schema, q)
        with lock:
            done[0] += 1
            print(f"[accuracy] {done[0]}/{len(questions)} {q.id} guarded={result.guarded}", file=sys.stderr, flush=True)
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, questions))
    return {"model": model, "results": [asdict(r) for r in results]}


def _rate(num: int, den: int) -> str:
    return "-" if not den else f"{num / den:.0%} ({num}/{den})"


def render_accuracy(data: dict[str, Any]) -> str:
    results = data["results"]
    lines = [f"# Accuracy: `{data['model']}`", "", "| Level | Questions | Correct, unguarded | Correct, guarded | Blocked by a guardrail |", "|---|---|---|---|---|"]
    for level in ("easy", "medium", "hard", "all"):
        group = [r for r in results if level == "all" or r["level"] == level]
        if group:
            lines.append(f"| {level} | {len(group)} | {_rate(sum(r['unguarded'] == 'correct' for r in group), len(group))} | "
                         f"{_rate(sum(r['guarded'] == 'correct' for r in group), len(group))} | {sum(r['guarded'] == 'blocked' for r in group)} |")
    over = [r for r in results if r["unguarded"] == "correct" and r["guarded"] != "correct"]
    lines += ["", f"**Correct SQL that a guardrail blocked or changed:** {len(over)}"]
    lines += [f"- `{r['id']}` {r['block_code']}: {r['detail']}\n  `{r['sql']}`" for r in over]
    misses = [r for r in results if r["guarded"] != "correct" and r not in over]
    lines += ["", f"**Wrong or failed answers ({len(misses)}):**"]
    lines += [f"- `{r['id']}` ({r['guarded']}) {r['question']}\n  `{r['sql'] or r['detail']}`" for r in misses]
    return "\n".join(lines) + "\n"
