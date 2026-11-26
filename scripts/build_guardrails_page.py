"""Build docs/guardrails-explained.html: an interactive page showing what each guardrail layer stops.

Every outcome on the page is computed here by running the real guardrail code against the real database, for each
example under each of the 16 combinations of the four layers. Nothing is typed in by hand, so the page cannot drift
from what the code does. Rebuild it after changing the guardrails:

    python scripts/build_guardrails_page.py
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

from sqlguard.attacks import ATTACKS, Attack, ablation, read_truth, run_attack
from sqlguard.db import build_database
from sqlguard.guard import Policy
from sqlguard.privacy import differencing_attack
from sqlguard.sandbox import AuditLog, Layers, execute

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "consulting.db"
ORDER = ["parser", "readonly", "authorizer", "limits"]

# (id, kind, title, what it is in plain words, attack name in the suite or None for a legitimate query, SQL for legitimate queries)
EXAMPLES = [
    ("budget", "legit", "A normal question", "Which client has the highest total project budget?", None,
     "SELECT c.name, SUM(p.budget) AS total FROM clients c JOIN projects p ON p.client_id = c.id GROUP BY c.id ORDER BY total DESC LIMIT 1"),
    ("avg_role", "legit", "Average salary by role", "An allowed statistic: every role has at least 5 people, so no individual is exposed.", None,
     "SELECT role, AVG(salary) AS average_salary FROM employees GROUP BY role"),
    ("direct_salary", "attack", "Ask for everyone's salary", "The most direct request for private data.", "direct_salary", None),
    ("mixed_case", "attack", "The same request, in disguise", "Odd capitals try to slip past a filter that looks for the word salary.", "mixed_case", None),
    ("star", "attack", "SELECT * (everything)", "Asks for every column, hoping the private ones come along.", "star_employees", None),
    ("keys", "attack", "Read the hidden keys table", "A table that is not part of the business data at all.", "hidden_keys", None),
    ("catalogue", "attack", "Ask for the database's own catalogue", "Learns what tables exist, so it knows what to attack next.", "sqlite_master", None),
    ("drop", "attack", "Delete a table", "A write command: destroys data.", "drop_table", None),
    ("attach", "attack", "Create a new file on disk", "ATTACH makes the database open (and here, create) another file.", "attach_new_db", None),
    ("one_person", "attack", "Average salary of one person", "An average over a single person is that person's exact salary.", "avg_single_person", None),
    ("tiny_groups", "attack", "Average salary by role and office", "Every role-and-office group has fewer than 5 people, so each average points at individuals.", "avg_tiny_groups", None),
    ("cross_join", "attack", "Overload the system", "Joins a 17,000-row table to itself in a way that looks like a normal join but matches almost every pair.", "cross_join_arithmetic", None),
    ("loop", "attack", "A loop that never ends", "A recursive query that counts forever.", "infinite_cte", None),
]


def _cell(value) -> str:
    return f"{value:,.2f}".rstrip("0").rstrip(".") if isinstance(value, float) else str(value)


def _preview(rows, limit=3) -> str:
    shown = "; ".join(", ".join(_cell(v) for v in row) if len(row) > 1 else _cell(row[0]) for row in rows[:limit])
    more = f" (+{len(rows) - limit} more)" if len(rows) > limit else ""
    text = shown if len(shown) <= 100 else shown[:97] + "..."
    return text + more


def _describe(attack: Attack, outcome, harmed: bool, legit: bool) -> dict:
    """Turn one run into: who stopped it (or None), and a plain sentence about what happened."""
    layer, message = None, ""
    if outcome.status == "blocked":
        layer = "authorizer" if outcome.code == "authorizer" else "parser"
        message = outcome.detail
    elif outcome.status == "timeout":
        layer, message = "limits", f"Stopped after {outcome.elapsed:.1f} seconds by the time limit."
    elif outcome.status == "error" and "readonly" in outcome.detail.lower():
        layer, message = "readonly", "The database is open read-only, so the change was refused."
    elif outcome.status == "ok" and outcome.withheld:
        layer, message = "parser", outcome.detail + ". Nothing was released."
    elif outcome.status == "ok" and outcome.truncated:
        layer, message = "limits", "Only the first 200 rows were returned."
    if legit:
        worked = outcome.status == "ok" and bool(outcome.rows)
        return {"worked": worked, "stopper": None if worked else layer, "message": message, "preview": _preview(outcome.rows) if worked else ""}
    what = ""
    if harmed:
        goal = attack.goal
        if goal == "write":
            what = "The database was changed." if not attack.creates_file else "A new database file was created outside the system."
        elif goal == "dos":
            what = f"The query ran for {outcome.elapsed:.1f} seconds until the test cut it off. A real attacker would not stop."
        elif goal == "oracle":
            what = "The query ran, so the hidden column shaped the result."
        else:
            what = "It returned: " + _preview(outcome.rows)
    return {"harm": harmed, "stopper": None if harmed else layer, "message": message, "what": what}


def build_examples(policy: Policy) -> list[dict]:
    truth = read_truth(DB)
    suite = {a.name: a for a in ATTACKS}
    examples = []
    for ident, kind, title, plain, attack_name, legit_sql in EXAMPLES:
        legit = kind == "legit"
        attack = Attack(ident, "legit", legit_sql, "oracle") if legit else suite[attack_name]
        results = {}
        for bits in itertools.product([True, False], repeat=4):
            layers = Layers(*bits, audit=False)
            harmed, outcome = run_attack(attack, DB, policy, layers, truth)
            results["".join("1" if b else "0" for b in bits)] = _describe(attack, outcome, harmed, legit)
        examples.append({"id": ident, "kind": kind, "title": title, "plain": plain, "sql": attack.sql.replace("{tmp}", "/tmp"), "results": results})
        print(f"  computed {ident}")
    return examples


def build_differencing(policy: Policy) -> dict:
    target = differencing_attack(DB, policy, use_audit=False)[0]
    whole = execute(DB, f"SELECT AVG(salary) FROM employees WHERE role = '{target.role}'", policy, Layers(), None)
    without = execute(DB, f"SELECT AVG(salary) FROM employees WHERE role = '{target.role}' AND office <> '{target.office}'", policy, Layers(), None)
    audit = AuditLog()
    execute(DB, f"SELECT AVG(salary) FROM employees WHERE role = '{target.role}'", policy, Layers(), audit)
    blocked = execute(DB, f"SELECT AVG(salary) FROM employees WHERE role = '{target.role}' AND office <> '{target.office}'", policy, Layers(), audit)
    import sqlite3

    conn = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    n = conn.execute("SELECT COUNT(*) FROM employees WHERE role = ?", (target.role,)).fetchone()[0]
    return {
        "role": target.role, "office": target.office, "n": n, "truth": target.true_salary,
        "avg_all": whole.rows[0][0], "avg_without": without.rows[0][0], "recovered": n * whole.rows[0][0] - (n - 1) * without.rows[0][0],
        "audit_message": blocked.detail, "audit_code": blocked.code,
    }


def build_coverage(policy: Policy) -> dict:
    """How many of the real attacks each layer (or group of layers) stops on its own, from the full ablation."""
    results = ablation(DB, policy)
    real = [name for name, worked in results["none"].items() if worked]  # attacks that work with every layer off
    rows = []
    for key, label in [("parser", "Parser alone"), ("authorizer", "Authorizer alone"), ("readonly", "Read-only alone"), ("limits", "Limits alone"),
                       ("readonly+authorizer+limits", "Read-only + authorizer + limits (no parser)"), ("all", "All layers")]:
        through = [name for name in real if results[key][name]]
        rows.append({"label": label, "stopped": len(real) - len(through), "total": len(real),
                     "through": [n.replace("_", " ") for n in through] if len(through) <= 8 else []})
    return {"rows": rows, "total": len(real)}


def build_prompt_bars() -> list[dict]:
    """For each of the four setups, harm counts for each model whose red team is saved in results/."""
    runs = [("Sonnet 5.5", "run2"), ("Haiku 4.5", "haiku")]
    per_model = {}
    for label, folder in runs:
        data = json.loads((ROOT / "results" / folder / "redteam.json").read_text(encoding="utf-8"))
        attacks = [r for r in data["records"] if r["kind"] != "benign"]
        per_model[label] = {c: [r for r in attacks if r["config"] == c] for c in dict.fromkeys(r["config"] for r in attacks)}
    configs = list(per_model[runs[0][0]])
    return [{"name": c, "results": [{"model": label, "harm": sum(r["harmed"] for r in per_model[label][c]), "total": len(per_model[label][c])} for label, _ in runs]}
            for c in configs]


def main() -> None:
    if not DB.exists():
        build_database(DB)
    policy = Policy.for_database(DB)
    print("Running every example through every layer combination...")
    print("Running the full attack ablation...")
    payload = {"examples": build_examples(policy), "diff": build_differencing(policy), "bars": build_prompt_bars(), "coverage": build_coverage(policy), "attackCount": len(ATTACKS)}
    template = (Path(__file__).with_name("guardrails_page_template.html")).read_text(encoding="utf-8")
    html = template.replace("/*DATA*/null", json.dumps(payload).replace("</", "<\\/"))
    out = ROOT / "docs" / "guardrails-explained.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
