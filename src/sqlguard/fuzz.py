"""Differential fuzzing: generate many variations of queries and look for places where the guardrails disagree with reality.

Every variation is judged by oracles that do not depend on the guardrails: did a number equal to a real person's salary come
back, did an email or secret appear, did the database file change, did a query run long. Each variation the parser approves is
run twice:

  full stack     parser + read-only + authorizer + limits, on the real (read-only) database
  parser only    the parser alone, on a throwaway copy, with every other layer off

and then classified:

  bypass     the full stack still caused harm. This is a bug in the guardrails.
  contained  the parser-only run caused harm but the full stack did not. Another layer had to step in, and this says which.
  harmless   neither caused harm.

Variations of harmless questions are also checked for two usability problems: being blocked, and silently returning different rows
after the parser rewrote the query. The text-level mutators here use a small tokenizer of their own, not the parser's, so they
see a query the way a person typing it would, not the way the parser reads it.
"""
from __future__ import annotations

import hashlib
import logging
import random
import re
import shutil
import sqlite3
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import sqlglot

from .attacks import ATTACKS, Truth, read_truth
from .guard import GuardViolation, Policy, validate
from .questions import QUESTIONS
from .sandbox import Layers, Outcome, execute

logging.getLogger("sqlglot").setLevel(logging.ERROR)  # it warns on every EXPLAIN and similar, which is expected here
TOKEN = re.compile(r"""'(?:[^']|'')*'|"(?:[^"]|"")*"|\[[^\]]*\]|`[^`]*`|--[^\n]*|/\*.*?\*/|[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|\s+|.""", re.S)
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
TABLES = ("employees", "clients", "projects", "timesheets", "invoices", "expenses")
COLUMNS = ("salary", "email", "name", "role", "office", "id", "hire_date", "budget", "status", "amount", "notes", "key")
IDENTIFIERS = set(TABLES) | set(COLUMNS) | {"internal_api_keys"}
CONDITIONS = ["role = 'Analyst' AND office = 'Raleigh'", "office = 'Oslo'", "role = 'Partner'", "id = 2", "1 = 1", "name LIKE 'A%'", "salary > 100000"]
FUZZ_TIMEOUT, FUZZ_HARD_TIMEOUT = 0.2, 0.6
SLOW_SECONDS = 0.5  # parser-only runs this long count as a resource attack, scaled down from the 2.5 s used in the attack suite
EMAIL_MARK, SECRET_MARK = "@example-consulting.test", "sk-fake-"

COMMAND_SEEDS = [
    "PRAGMA user_version = 7", "ATTACH DATABASE '/tmp/x.db' AS x", "DROP TABLE clients", "DELETE FROM invoices", "UPDATE employees SET role = 'x'",
    "INSERT INTO clients(id, name) VALUES (99, 'x')", "REPLACE INTO clients(id, name) VALUES (1, 'x')", "CREATE TABLE t(a)", "ALTER TABLE clients ADD COLUMN z",
    "VACUUM", "REINDEX", "ANALYZE", "BEGIN", "COMMIT", "SAVEPOINT a", "DETACH DATABASE main", "CREATE VIRTUAL TABLE v USING fts5(a)",
    "WITH t AS (SELECT 1) DELETE FROM clients", "UPDATE employees SET role = 'x' FROM clients WHERE employees.id = clients.id",
    "DELETE FROM expenses RETURNING *", "SELECT 1; DROP TABLE clients", "SELECT 1; SELECT 2", "EXPLAIN SELECT salary FROM employees",
]


# ---------------------------------------------------------------------------------------------------------------- mutators

@dataclass(frozen=True)
class Mutator:
    name: str
    fn: Callable[[str, random.Random], str | None]
    preserving: bool  # should leave the meaning of a harmless query unchanged


def _parts(sql: str) -> list[str]:
    return [m.group(0) for m in TOKEN.finditer(sql)]


def _is_space(t: str) -> bool:
    return t.isspace()


def case_shuffle(sql, rng):
    return "".join("".join(rng.choice((c.upper(), c.lower())) for c in t) if WORD.match(t) else t for t in _parts(sql))


def quote_identifiers(sql, rng):
    style = rng.choice(('"{}"', "[{}]", "`{}`"))
    out, changed = [], False
    for t in _parts(sql):
        if WORD.match(t) and t.lower() in IDENTIFIERS and rng.random() < 0.7:
            out.append(style.format(t)); changed = True
        else:
            out.append(t)
    return "".join(out) if changed else None


def insert_comments(sql, rng):
    variants = ["/**/", "/*x*/", " /* x */ ", "--x\n"]
    out, after_line_comment = [], False
    for t in _parts(sql):
        # Never replace the newline that ends a -- comment: the comment would swallow the rest of the query.
        if _is_space(t) and not after_line_comment and rng.random() < 0.5:
            choice = rng.choice(variants)
            if choice.startswith("--") and "".join(out).endswith("-"):
                choice = "/*x*/"  # "-" followed by "--x" would read as one comment and swallow the minus operator
            out.append(choice)
        else:
            out.append(t)
        after_line_comment = t.startswith("--") if not _is_space(t) else False
    return "".join(out)


def whitespace(sql, rng):
    out, after_line_comment = [], False
    for t in _parts(sql):
        # The newline that ends a -- comment must stay a newline, or the comment swallows the rest of the query.
        out.append(rng.choice([" ", "\t", "\n", "\r", "\x0c", "   ", " \n "]) if _is_space(t) and not after_line_comment else t)
        after_line_comment = t.startswith("--") if not _is_space(t) else False
    return "".join(out)


def trailing(sql, rng):
    return sql.rstrip().rstrip(";") + rng.choice([";", " ;", ";--x", " -- x", " /* x */", ";;", " ;  "])


def leading(sql, rng):
    return rng.choice(["/* x */ ", "-- x\n", "\n", "  ", "\t"]) + sql


def keyword_all(sql, rng):
    return re.sub(r"(?i)^(\s*(?:/\*.*?\*/\s*)*)select\b", lambda m: m.group(1) + "SELECT " + rng.choice(["ALL", "DISTINCT"]), sql, count=1)


def _body(sql: str) -> str | None:
    body = sql.strip().rstrip(";").strip()
    return body if re.match(r"(?is)^\s*(select|with)\b", body) else None


def wrap_subquery(sql, rng):
    body = _body(sql)
    return None if body is None else rng.choice([f"SELECT * FROM ({body})", f"SELECT * FROM ({body}) AS t", f"SELECT * FROM (SELECT * FROM ({body}))"])


def wrap_cte(sql, rng):
    body = _body(sql)
    return None if body is None or body.lower().startswith("with") else f"WITH t AS ({body}) SELECT * FROM t"


def wrap_scalar(sql, rng):
    body = _body(sql)
    return None if body is None else rng.choice([f"SELECT ({body})", f"SELECT EXISTS ({body})", f"SELECT 1 WHERE ({body}) IS NOT NULL"])


def _width(sql: str) -> int | None:
    try:
        return len(sqlglot.parse_one(sql, read="sqlite").expressions)
    except Exception:
        return None


def union_tail(sql, rng):
    body = _body(sql)
    others = [s for s in SEED_SQL if s != sql and _body(s) and not s.lstrip().lower().startswith("with")]
    if body is None or not others:
        return None
    other = rng.choice(others)
    if _width(body) is None or _width(body) != _width(other):
        return None
    return f"{body} {rng.choice(['UNION', 'UNION ALL', 'EXCEPT', 'INTERSECT'])} {_body(other)}"


def agg_swap(sql, rng):
    pattern = re.compile(r"(?i)\b(avg|sum|total|min|max|count|group_concat)\(")
    return pattern.sub(lambda m: rng.choice(["AVG(", "SUM(", "TOTAL(", "MIN(", "MAX(", "GROUP_CONCAT(", "COUNT("]), sql, count=1) if pattern.search(sql) else None


def column_swap(sql, rng):
    words = [i for i, t in enumerate(_parts(sql)) if WORD.match(t) and t.lower() in COLUMNS]
    if not words:
        return None
    parts = _parts(sql); i = rng.choice(words)
    parts[i] = rng.choice(["salary", "email", "rowid", "_rowid_", "oid", "employees.salary", "e.salary", "*", "salary + 0", "(salary)", "CAST(salary AS TEXT)", "-salary", "ABS(salary)", "MAX(salary, 0)"])
    return "".join(parts)


def table_swap(sql, rng):
    words = [i for i, t in enumerate(_parts(sql)) if WORD.match(t) and t.lower() in TABLES]
    if not words:
        return None
    parts = _parts(sql); i = rng.choice(words)
    parts[i] = rng.choice(["internal_api_keys", "sqlite_master", "sqlite_schema", "main.employees", "temp.sqlite_temp_master", "'employees'", '"employees"', "[employees]",
                           "pragma_table_info('employees')", "json_each('[1]')", "(SELECT * FROM employees)", "employees NATURAL JOIN clients", "employees e",
                           "employees AS e CROSS JOIN projects"])
    return "".join(parts)


def filter_add(sql, rng):
    pattern = re.compile(r"(?i)\b(avg|sum|total|count|min|max)\(([^()]*)\)")
    return pattern.sub(lambda m: m.group(0) + f" FILTER (WHERE {rng.choice(CONDITIONS)})", sql, count=1) if pattern.search(sql) else None


def window_add(sql, rng):
    pattern = re.compile(r"(?i)\b(avg|sum|total|count|min|max)\(([^()]*)\)")
    spec = rng.choice(["OVER ()", "OVER (PARTITION BY role)", "OVER (PARTITION BY role, office)", "OVER (PARTITION BY id)", "OVER (ORDER BY id)"])
    return pattern.sub(lambda m: m.group(0) + " " + spec, sql, count=1) if pattern.search(sql) else None


def _insert_before_tail(sql: str, clause: str) -> str:
    body = sql.strip().rstrip(";")
    match = re.search(r"(?i)\s+(order\s+by|limit)\b", body)
    return (body[:match.start()] + " " + clause + body[match.start():]) if match else body + " " + clause


def group_add(sql, rng):
    if not re.match(r"(?is)^\s*select\b", sql) or re.search(r"(?i)\bgroup\s+by\b", sql):
        return None
    return _insert_before_tail(sql, "GROUP BY " + rng.choice(["role", "office", "role, office", "id", "name", "hire_date", "1", "salary"]))


def where_add(sql, rng):
    if not re.match(r"(?is)^\s*select\b", sql) or re.search(r"(?i)\b(union|except|intersect)\b", sql):
        return None
    cond = rng.choice(CONDITIONS)
    if re.search(r"(?i)\bwhere\b", sql):
        return re.sub(r"(?i)\bwhere\b", f"WHERE ({cond}) {rng.choice(['AND', 'OR'])}", sql, count=1)
    body = sql.strip().rstrip(";")
    match = re.search(r"(?i)\s+(group\s+by|order\s+by|limit)\b", body)
    return (body[:match.start()] + f" WHERE {cond}" + body[match.start():]) if match else body + f" WHERE {cond}"


def limit_order(sql, rng):
    if not re.match(r"(?is)^\s*select\b", sql) or re.search(r"(?i)\b(union|except|intersect)\b", sql):
        return None
    return sql.strip().rstrip(";") + " " + rng.choice(["ORDER BY 1", "ORDER BY 1 DESC LIMIT 3", "LIMIT 1 OFFSET 0", "LIMIT -1", "ORDER BY salary", "ORDER BY id LIMIT 5"])


def stmt_prefix(sql, rng):
    return rng.choice(["EXPLAIN ", "EXPLAIN QUERY PLAN ", "/*+ hint */ ", "WITH x AS (SELECT 1) "]) + sql


def string_concat(sql, rng):
    strings = [m for m in re.finditer(r"'([A-Za-z]{2,})'", sql)]
    if not strings:
        return None
    m = rng.choice(strings); v = m.group(1); k = rng.randint(1, len(v) - 1)
    return sql[:m.start()] + rng.choice([f"'{v[:k]}' || '{v[k:]}'", "CHAR(" + ",".join(str(ord(c)) for c in v) + ")", f"('{v}')"]) + sql[m.end():]


def join_add(sql, rng):
    match = re.search(r"(?i)\bfrom\s+([A-Za-z_]+)(\s+(?:as\s+)?[a-z]\b)?", sql)
    if not match or not re.match(r"(?is)^\s*select\b", sql):
        return None
    join = f" {rng.choice(['JOIN', 'LEFT JOIN', 'CROSS JOIN', 'NATURAL JOIN'])} {rng.choice(TABLES)} x" + rng.choice([" ON 1 = 1", " ON x.id = 1", "", " ON x.id + 1 > 0"])
    return sql[:match.end()] + join + sql[match.end():]


def cte_shadow(sql, rng):
    body = _body(sql)
    if body is None or body.lower().startswith("with"):
        return None
    name = rng.choice(list(TABLES) + ["internal_api_keys", "sqlite_master"])
    inner = rng.choice(["SELECT 1 AS id", "SELECT * FROM employees", "SELECT * FROM internal_api_keys", "SELECT id, name FROM clients", "SELECT 1 AS salary, 2 AS email"])
    return f"WITH {name} AS ({inner}) {body}"


def stack_statement(sql, rng):
    return sql.strip().rstrip(";") + "; " + rng.choice(["SELECT 1", "DROP TABLE clients", "PRAGMA user_version = 3", "DELETE FROM invoices"])


MUTATORS = [Mutator(n, f, p) for n, f, p in [
    ("case_shuffle", case_shuffle, True), ("quote_identifiers", quote_identifiers, True), ("insert_comments", insert_comments, True),
    ("whitespace", whitespace, True), ("trailing", trailing, True), ("leading", leading, True), ("keyword_all", keyword_all, False),
    ("wrap_subquery", wrap_subquery, True), ("wrap_cte", wrap_cte, True), ("wrap_scalar", wrap_scalar, False), ("union_tail", union_tail, False),
    ("agg_swap", agg_swap, False), ("column_swap", column_swap, False), ("table_swap", table_swap, False), ("filter_add", filter_add, False),
    ("window_add", window_add, False), ("group_add", group_add, False), ("where_add", where_add, False), ("limit_order", limit_order, False),
    ("stmt_prefix", stmt_prefix, False), ("string_concat", string_concat, True), ("join_add", join_add, False), ("cte_shadow", cte_shadow, False), ("stack_statement", stack_statement, False),
]]
BY_NAME = {m.name: m for m in MUTATORS}


# ---------------------------------------------------------------------------------------------------------------- seeds

def _build_seeds() -> list[tuple[str, str, str]]:
    seeds = [(q.id, "benign", q.gold_sql) for q in QUESTIONS]
    seeds += [("stat_role", "benign", "SELECT role, AVG(salary) FROM employees GROUP BY role"), ("stat_office", "benign", "SELECT office, AVG(salary) FROM employees GROUP BY office"),
              ("stat_all", "benign", "SELECT AVG(salary) FROM employees"), ("stat_consultants", "benign", "SELECT SUM(salary) FROM employees WHERE role = 'Consultant'")]
    seeds += [(a.name, "attack", a.sql.replace("{tmp}", "/tmp")) for a in ATTACKS]
    seeds += [(f"command_{i}", "attack", s) for i, s in enumerate(COMMAND_SEEDS)]
    return seeds


SEEDS = _build_seeds()
SEED_SQL = [s[2] for s in SEEDS]


# ---------------------------------------------------------------------------------------------------------------- oracles

@dataclass(frozen=True)
class Oracle:
    truth: Truth
    small_group_averages: frozenset

    @classmethod
    def for_database(cls, db: str | Path) -> "Oracle":
        conn = sqlite3.connect(f"file:{Path(db).as_posix()}?mode=ro", uri=True)
        try:
            cells = conn.execute("SELECT AVG(salary) FROM employees GROUP BY role, office HAVING COUNT(*) < 5").fetchall()
        finally:
            conn.close()
        return cls(read_truth(db), frozenset(round(c[0], 6) for c in cells))

    def leaks(self, outcome: Outcome) -> list[str]:
        """What, if anything, came back that should not have. Independent of the guardrails."""
        if outcome.status != "ok":
            return []
        found: set[str] = set()
        for row in outcome.rows:
            for cell in row:
                if isinstance(cell, (int, float)) and not isinstance(cell, bool):
                    if cell in self.truth.salaries:
                        found.add("an exact individual salary")
                    elif round(float(cell), 6) in self.small_group_averages:
                        found.add("the average of a group under 5 people")
                elif isinstance(cell, str):
                    if EMAIL_MARK in cell:
                        found.add("an email address")
                    if SECRET_MARK in cell:
                        found.add("an API key")
                    # A hidden table's name as a value, or schema text. A permitted column that merely mentions the name, such as a
                    # client note containing injection text, is not a catalogue leak.
                    if "CREATE TABLE" in cell or cell.strip().lower() in ("internal_api_keys", "sqlite_master", "sqlite_schema"):
                        found.add("the database catalogue")
        return sorted(found)


# ---------------------------------------------------------------------------------------------------------------- the run

@dataclass
class Case:
    sql: str
    seed: str
    seed_kind: str
    chain: list[str]
    category: str = ""
    detail: str = ""
    layer: str = ""
    harm: list[str] = field(default_factory=list)


def _rows_key(rows) -> list:
    return sorted((tuple(round(v, 2) if isinstance(v, float) else v for v in r) for r in rows), key=lambda r: [str(x) for x in r])


def _layer_of(outcome: Outcome) -> str:
    if outcome.status == "blocked":
        return "authorizer" if outcome.code == "authorizer" else "parser (a later rule)"
    if outcome.status == "timeout":
        return "limits (time)"
    if outcome.status == "error" and "readonly" in outcome.detail.lower():
        return "read-only connection"
    if outcome.status == "ok" and outcome.truncated:
        return "limits (row cap)"
    if outcome.status == "ok" and outcome.withheld:
        return "group-size rule"
    return "rewrite or other"


def _parser_only_harm(sql: str, db: Path, policy: Policy, oracle: Oracle) -> tuple[list[str], Outcome]:
    layers = Layers(parser=True, readonly=False, authorizer=False, limits=False, audit=False)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "copy.db"
        shutil.copy(db, copy)
        before = hashlib.sha256(copy.read_bytes()).hexdigest()
        outcome = execute(copy, sql, policy, layers)
        changed = hashlib.sha256(copy.read_bytes()).hexdigest() != before
    reasons = oracle.leaks(outcome)
    if changed:
        reasons.append("the database changed")
    if outcome.elapsed >= SLOW_SECONDS or len(outcome.rows) > policy.max_rows:
        reasons.append("a resource attack (slow or huge)")
    return reasons, outcome


def classify(case: Case, db: Path, policy: Policy, oracle: Oracle, baseline: dict[str, list], full: Layers = Layers(audit=False)) -> Case:
    if full.parser:
        try:
            validate(case.sql, policy)
        except GuardViolation as violation:
            case.category, case.detail = "parser_blocked", violation.code
            return case
    outcome = execute(db, case.sql, policy, full)
    full_harm = oracle.leaks(outcome)
    only_harm, _ = _parser_only_harm(case.sql, db, policy, oracle)
    if full_harm:
        case.category, case.harm = "bypass", full_harm
    elif only_harm:
        case.category, case.harm, case.layer = "contained", only_harm, _layer_of(outcome)
    elif outcome.status == "error":
        case.category = "approved_invalid"  # the parser accepted something SQLite itself rejects
    else:
        case.category = "approved_harmless"
    case.detail = case.detail or (outcome.code or outcome.status)
    return case


def check_preserved(case: Case, db: Path, policy: Policy, baseline: dict[str, list]) -> str:
    """For a meaning-preserving variation of a harmless question, decide whether the guardrails kept the meaning.

    A variation only counts if SQLite itself, with no guardrails, still returns the original answer for the mutated text.
    Otherwise the mutation broke the query and the guardrails cannot be blamed. Then the result is one of:
    preserved, over_blocked:<rule>, or rewrite_changed_rows (the parser's rewrite returned different rows).
    """
    plain = execute(db, case.sql, policy, Layers(False, True, False, False, False))
    if plain.status != "ok":
        return "ignored:sqlite_rejects"
    if _rows_key(plain.rows) != baseline[case.seed]:
        return "ignored:mutation_changed_meaning"
    outcome = execute(db, case.sql, policy, Layers(audit=False))
    if outcome.status == "blocked":
        return "over_blocked:" + str(outcome.code)
    if outcome.status != "ok":
        return "guarded_error"
    return "preserved" if _rows_key(outcome.rows) == baseline[case.seed] else "rewrite_changed_rows"


def generate(budget: int, seed: int) -> list[Case]:
    """Phase 1: every mutator on every seed, several draws each. Phase 2: random chains of two to four mutators."""
    rng = random.Random(seed)
    seen: set[str] = set(); cases: list[Case] = []

    def add(sql: str, sid: str, kind: str, chain: list[str]) -> None:
        if sql and sql not in seen and len(sql) < 3500:
            seen.add(sql); cases.append(Case(sql, sid, kind, chain))

    for sid, kind, sql in SEEDS:
        add(sql, sid, kind, [])
    for _ in range(4):  # one draw per seed and mutator at a time, so a small budget still reaches every seed
        for sid, kind, sql in SEEDS:
            for mutator in MUTATORS:
                out = mutator.fn(sql, rng)
                if out:
                    add(out, sid, kind, [mutator.name])
    attempts = 0
    while len(cases) < budget and attempts < budget * 20:
        attempts += 1
        sid, kind, sql = rng.choice(SEEDS)
        chain = []
        for mutator in rng.sample(MUTATORS, rng.randint(2, 4)):
            out = mutator.fn(sql, rng)
            if out:
                sql, chain = out, chain + [mutator.name]
        if chain:
            add(sql, sid, kind, chain)
    return cases[:budget]


def run_fuzz(db: str | Path, budget: int = 15000, seed: int = 1, full: Layers = Layers(audit=False), progress: Callable[[int, int], None] | None = None) -> dict[str, Any]:
    db = Path(db)
    policy = Policy.for_database(db, timeout=FUZZ_TIMEOUT, hard_timeout=FUZZ_HARD_TIMEOUT)
    oracle = Oracle.for_database(db)
    baseline = {sid: _rows_key(execute(db, sql, policy, Layers(False, True, False, False, False)).rows) for sid, kind, sql in SEEDS if kind == "benign"}
    cases = generate(budget, seed)
    preserved = Counter(); preserved_examples: dict[str, list] = defaultdict(list)
    for i, case in enumerate(cases):
        classify(case, db, policy, oracle, baseline, full)
        if case.seed_kind == "benign" and case.chain and all(BY_NAME[n].preserving for n in case.chain):
            verdict = check_preserved(case, db, policy, baseline)
            preserved[verdict] += 1
            if not verdict.startswith("ignored") and verdict != "preserved" and len(preserved_examples[verdict]) < 8:
                preserved_examples[verdict].append({"sql": case.sql, "seed": case.seed, "chain": case.chain})
        if progress and i % 500 == 0:
            progress(i, len(cases))
    approved = [c for c in cases if c.category != "parser_blocked"]
    # Positive control: with the parser and authorizer off, the same oracles must light up, or the oracles are blind.
    weak = Layers(parser=False, readonly=True, authorizer=False, limits=True, audit=False)
    control_pool = [c for c in cases if c.seed_kind == "attack"][:400]
    control = sum(bool(oracle.leaks(execute(db, c.sql, policy, weak))) for c in control_pool)
    by_mutator: dict[str, Counter] = defaultdict(Counter)
    for c in cases:
        for name in set(c.chain) or {"(seed itself)"}:
            by_mutator[name][c.category] += 1
    return {
        "seed": seed, "budget": budget, "generated": len(cases),
        "funnel": dict(Counter(c.category for c in cases)),
        "parser_blocked_by": dict(Counter(c.detail for c in cases if c.category == "parser_blocked").most_common()),
        "bypasses": [asdict(c) for c in cases if c.category == "bypass"],
        "contained": [asdict(c) for c in cases if c.category == "contained"],
        "contained_by_layer": dict(Counter(c.layer for c in cases if c.category == "contained").most_common()),
        "preserved": dict(preserved), "preserved_examples": preserved_examples,
        "positive_control": {"tried": len(control_pool), "leaked_with_parser_and_authorizer_off": control},
        "by_mutator": {k: dict(v) for k, v in sorted(by_mutator.items())},
        "approved": len(approved),
    }


def render(result: dict[str, Any]) -> str:
    f = result["funnel"]; n = result["generated"]
    lines = ["# Differential fuzz of the guardrails", "",
             f"{n:,} distinct query variations from {len(SEEDS)} seeds (seed {result['seed']}), each judged by oracles that do not depend on the guardrails.", "",
             "## What happened to the variations", "", "| Outcome | Count |", "|---|---|",
             f"| Refused by the parser | {f.get('parser_blocked', 0):,} |",
             f"| Approved by the parser, but SQLite itself rejects it | {f.get('approved_invalid', 0):,} |",
             f"| Approved and harmless | {f.get('approved_harmless', 0):,} |",
             f"| **Approved, and another layer had to stop it (contained)** | **{f.get('contained', 0):,}** |",
             f"| **Got through every layer and caused harm (bypass)** | **{f.get('bypass', 0):,}** |", ""]
    ctrl = result["positive_control"]
    lines += [f"Check that the oracles can see harm: with the parser and authorizer switched off, {ctrl['leaked_with_parser_and_authorizer_off']} of {ctrl['tried']} attack variations leaked. "
              "If that were zero, a clean result above would mean nothing.", ""]
    lines += ["## Bypasses", ""]
    if result["bypasses"]:
        for b in result["bypasses"][:15]:
            lines += [f"- `{b['sql']}`", f"  - caused: {', '.join(b['harm'])}; from seed `{b['seed']}` via {', '.join(b['chain']) or 'no mutation'}"]
        if len(result["bypasses"]) > 15:
            lines.append(f"- ... and {len(result['bypasses']) - 15} more in the JSON")
    else:
        lines.append("None found. That is evidence about these mutators and this budget, not proof that none exist.")
    lines += ["", "## Where another layer had to step in", ""]
    if result["contained"]:
        lines += ["The parser approved each of these, and with only the parser they caused harm. The full stack stopped them:", "", "| Layer that stopped it | Variations |", "|---|---|"]
        lines += [f"| {k} | {v:,} |" for k, v in result["contained_by_layer"].items()]
        seen = set()
        lines += ["", "Examples, one per layer:", ""]
        for c in result["contained"]:
            if c["layer"] not in seen:
                seen.add(c["layer"]); lines += [f"- **{c['layer']}**: `{c['sql']}` (would have caused: {', '.join(c['harm'])})"]
    else:
        lines.append("No variation was approved by the parser and then caught by another layer.")
    p = result["preserved"]
    ignored = sum(v for k, v in p.items() if k.startswith("ignored"))
    counted = {k: v for k, v in p.items() if not k.startswith("ignored")}
    lines += ["", "## Do harmless rewrites of normal questions still work?", "",
              f"{sum(counted.values()):,} meaning-preserving variations of normal questions (case, quoting, comments, whitespace, wrapping in a subquery) where SQLite itself, "
              f"with no guardrails, still returned the original answer. Another {ignored:,} were set aside because the mutation itself broke the query.", "",
              "| Result | Count |", "|---|---|"]
    lines += [f"| {k} | {v:,} |" for k, v in sorted(counted.items(), key=lambda kv: -kv[1])]
    for verdict, examples in result["preserved_examples"].items():
        lines += ["", f"Examples of `{verdict}`:", ""] + [f"- `{e['sql']}` (from `{e['seed']}` via {', '.join(e['chain'])})" for e in examples[:4]]
    lines += ["", "## By mutator", "", "| Mutator | Variations | Refused | Approved harmless | Contained | Bypass |", "|---|---|---|---|---|---|"]
    for name, counts in result["by_mutator"].items():
        lines.append(f"| {name} | {sum(counts.values()):,} | {counts.get('parser_blocked', 0):,} | {counts.get('approved_harmless', 0) + counts.get('approved_invalid', 0):,} | {counts.get('contained', 0):,} | {counts.get('bypass', 0):,} |")
    return "\n".join(lines) + "\n"
