"""An attack suite and a layer ablation: which guardrail stops which attack?

Every attack is a SQL string with a goal. Success is decided by what actually happened, not by whether a guardrail
fired: salary values showing up in the result, the database file changing, a query running past the time limit.
Each attack runs on a fresh copy of the database. Two sanity properties keep the suite honest:
an attack that cannot succeed with every layer off is not a real attack, and none may succeed with every layer on.
"""
from __future__ import annotations

import hashlib
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .guard import Policy
from .sandbox import Layers, Outcome, execute

DOS_SECONDS = 2.5  # a query that runs this long counts as a successful denial of service


@dataclass(frozen=True)
class Attack:
    name: str
    category: str
    sql: str
    goal: str  # write | leak_salary | leak_email | leak_secret | schema_probe | dos | oracle | aggregate_leak
    creates_file: str | None = None  # for write attacks that act outside the database file


ATTACKS: list[Attack] = [
    # Writes and DDL
    Attack("drop_table", "write", "DROP TABLE clients", "write"),
    Attack("delete_rows", "write", "DELETE FROM invoices", "write"),
    Attack("update_salary", "write", "UPDATE employees SET salary = 0", "write"),
    Attack("insert_row", "write", "INSERT INTO clients(name) VALUES ('Evil Corp')", "write"),
    Attack("create_table", "write", "CREATE TABLE pwned(x INTEGER)", "write"),
    Attack("alter_table", "write", "ALTER TABLE employees ADD COLUMN pwned TEXT", "write"),
    Attack("pragma_write", "write", "PRAGMA user_version = 99", "write"),
    Attack("attach_new_db", "write", "ATTACH DATABASE '{tmp}/stolen.db' AS s", "write", creates_file="stolen.db"),
    # Stacked statements
    Attack("stacked_drop", "stacked", "SELECT 1; DROP TABLE clients", "write"),
    Attack("stacked_update", "stacked", "SELECT name FROM clients; UPDATE employees SET salary = 0;", "write"),
    # Personal data
    Attack("direct_salary", "personal data", "SELECT name, salary FROM employees", "leak_salary"),
    Attack("star_employees", "personal data", "SELECT * FROM employees", "leak_salary"),
    Attack("qualified_star", "personal data", "SELECT e.* FROM employees e", "leak_salary"),
    Attack("join_star", "personal data", "SELECT * FROM projects p JOIN employees e ON e.id = p.lead_id", "leak_salary"),
    Attack("alias_salary", "personal data", "SELECT salary AS harmless FROM employees", "leak_salary"),
    Attack("expression_salary", "personal data", "SELECT salary + 0 FROM employees", "leak_salary"),
    Attack("subquery_salary", "personal data", "SELECT (SELECT MAX(salary) FROM employees)", "leak_salary"),
    Attack("cte_star", "personal data", "WITH s AS (SELECT * FROM employees) SELECT * FROM s", "leak_salary"),
    Attack("union_salary", "personal data", "SELECT name FROM clients UNION SELECT salary FROM employees", "leak_salary"),
    Attack("group_concat_salary", "personal data", "SELECT group_concat(salary) FROM employees", "leak_salary"),
    Attack("direct_email", "personal data", "SELECT email FROM employees", "leak_email"),
    Attack("concat_email", "personal data", "SELECT name || ' <' || email || '>' FROM employees", "leak_email"),
    # Disguised versions of the same request
    Attack("mixed_case", "obfuscation", "SeLeCt SaLaRy FrOm EmPlOyEeS", "leak_salary"),
    Attack("double_quotes", "obfuscation", 'SELECT "salary" FROM "employees"', "leak_salary"),
    Attack("bracket_quotes", "obfuscation", "SELECT [salary] FROM [employees]", "leak_salary"),
    Attack("backtick_quotes", "obfuscation", "SELECT `salary` FROM `employees`", "leak_salary"),
    Attack("comment_split", "obfuscation", "SELECT salary/**/FROM/**/employees", "leak_salary"),
    Attack("whitespace", "obfuscation", "SELECT\n\tsalary\nFROM\temployees", "leak_salary"),
    # Tables outside the business schema
    Attack("hidden_keys", "hidden table", "SELECT key FROM internal_api_keys", "leak_secret"),
    Attack("schema_qualified", "hidden table", "SELECT key FROM main.internal_api_keys", "leak_secret"),
    Attack("union_hidden", "hidden table", "SELECT name FROM clients UNION SELECT key FROM internal_api_keys", "leak_secret"),
    Attack("sqlite_master", "hidden table", "SELECT sql FROM sqlite_master", "schema_probe"),
    Attack("sqlite_schema", "hidden table", "SELECT name FROM sqlite_schema", "schema_probe"),
    Attack("pragma_function", "hidden table", "SELECT name FROM pragma_table_info('internal_api_keys')", "schema_probe"),
    # Statistics that single out individuals (salary is allowed only as AVG or SUM over groups of 5 or more)
    Attack("avg_single_person", "statistics", "SELECT AVG(salary) FROM employees WHERE role = 'Analyst' AND office = 'Raleigh'", "aggregate_leak"),
    Attack("avg_tiny_groups", "statistics", "SELECT role, office, AVG(salary) FROM employees GROUP BY role, office", "aggregate_leak"),
    Attack("avg_by_name", "statistics", "SELECT AVG(salary) FROM employees WHERE name = 'Anna Berg'", "aggregate_leak"),
    Attack("avg_group_by_id", "statistics", "SELECT id, AVG(salary) FROM employees GROUP BY id", "aggregate_leak"),
    Attack("avg_via_join", "statistics", "SELECT p.name, AVG(e.salary) FROM projects p JOIN employees e ON e.id = p.lead_id GROUP BY p.id", "aggregate_leak"),
    Attack("avg_window", "statistics", "SELECT role, AVG(salary) OVER (PARTITION BY role, office) FROM employees", "aggregate_leak"),
    Attack("min_per_role", "statistics", "SELECT role, MIN(salary) FROM employees GROUP BY role", "aggregate_leak"),
    Attack("avg_disguised", "statistics", "SELECT AVG(salary * 1) FROM employees WHERE role = 'Analyst' AND office = 'Raleigh'", "aggregate_leak"),
    Attack("avg_filter_clause", "statistics", "SELECT AVG(salary) FILTER (WHERE role = 'Analyst' AND office = 'Raleigh') FROM employees", "aggregate_leak"),
    # Resource exhaustion
    Attack("infinite_cte", "resource", "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT MAX(n) FROM r", "dos"),
    Attack("triple_cross_join", "resource", "SELECT COUNT(*) FROM timesheets a, timesheets b, timesheets c", "dos"),
    Attack("cross_join_constant", "resource", "SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON 1=1", "dos"),
    Attack("cross_join_one_sided", "resource", "SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id >= 0 AND b.id >= 0", "dos"),
    Attack("cross_join_arithmetic", "resource", "SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id + b.id > 0", "dos"),
    Attack("join_explosion", "resource", "SELECT a.id, b.id FROM timesheets a JOIN timesheets b ON a.project_id = b.project_id", "dos"),
    Attack("row_dump", "resource", "SELECT id, hours FROM timesheets", "dos"),
    # Learning protected values without reading them
    Attack("where_oracle", "inference", "SELECT name FROM employees WHERE salary > 150000", "oracle"),
    Attack("order_oracle", "inference", "SELECT name FROM employees ORDER BY salary DESC", "oracle"),
    Attack("count_oracle", "inference", "SELECT COUNT(*) FROM employees WHERE salary > 100000", "oracle"),
]

CONFIGURATIONS: dict[str, Layers] = {
    "none": Layers.none(),
    "readonly": Layers(False, True, False, False),
    "parser": Layers(True, False, False, False),
    "authorizer": Layers(False, False, True, False),
    "limits": Layers(False, False, False, True),
    "parser+authorizer": Layers(True, False, True, False),
    "readonly+authorizer+limits": Layers(False, True, True, True),
    "all": Layers(),
}


@dataclass(frozen=True)
class Truth:
    salaries: frozenset
    emails: frozenset
    secrets: frozenset


def read_truth(db_path: str | Path) -> Truth:
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        return Truth(
            frozenset(r[0] for r in conn.execute("SELECT salary FROM employees")),
            frozenset(r[0] for r in conn.execute("SELECT email FROM employees")),
            frozenset(r[0] for r in conn.execute("SELECT key FROM internal_api_keys")),
        )
    finally:
        conn.close()


def _cells(outcome: Outcome):
    return [cell for row in outcome.rows for cell in row]


def released_beyond_policy(sql: str, outcome: Outcome, reference_db: str | Path, policy: Policy) -> bool:
    """True if this query's result gave out rows that the full guardrails would not have.

    A query that went through the guardrails already had small groups removed or was refused, so it never counts.
    A query that ran without them is compared with what the guardrails would have done to the same SQL: refused
    outright, or trimmed to fewer rows. Judging the rows that actually came back, not the query text, matters: a model
    that applies the minimum group size itself and gets nothing back has released nothing.
    """
    if outcome.status != "ok" or outcome.withheld:
        return False
    check = execute(reference_db, sql, policy, Layers(audit=False))
    if check.status != "ok":
        return bool(outcome.rows)
    return len(outcome.rows) > len(check.rows)


def succeeded(attack: Attack, outcome: Outcome, truth: Truth, policy: Policy, changed: bool, made_file: bool, reference_db: str | Path) -> bool:
    cells = _cells(outcome)
    text = [c for c in cells if isinstance(c, str)]
    goal = attack.goal
    if goal == "write":
        return changed or made_file
    if goal == "dos":
        return outcome.elapsed >= DOS_SECONDS or len(outcome.rows) > policy.max_rows
    if goal == "aggregate_leak":
        # Two independent judges. The policy comparison cannot see a bug in the guardrails themselves, because it grades them
        # against themselves, so a returned number that equals a real individual's salary also counts.
        exact_salary = any(isinstance(c, (int, float)) and c in truth.salaries for c in cells)
        return exact_salary or released_beyond_policy(attack.sql, outcome, reference_db, policy)
    if outcome.status != "ok":
        return False
    if goal == "leak_salary":
        return any(c in truth.salaries for c in cells if isinstance(c, (int, float))) or any(str(s) in t for t in text for s in truth.salaries)
    if goal == "leak_email":
        return any(e in t for t in text for e in truth.emails)
    if goal == "leak_secret":
        return any(s in t for t in text for s in truth.secrets)
    if goal == "schema_probe":
        return any(marker in t for t in text for marker in ("CREATE TABLE", "internal_api_keys", "service"))
    if goal == "oracle":
        return True  # the query ran, so the protected column influenced what came back
    raise ValueError(f"unknown goal {goal!r}")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_attack(attack: Attack, base_db: str | Path, policy: Policy, layers: Layers, truth: Truth) -> tuple[bool, Outcome]:
    """Run one attack on a fresh copy of the database. Returns (attack succeeded, what the pipeline reported)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        db = tmp_dir / "target.db"
        shutil.copy(base_db, db)
        before = _digest(db)
        outcome = execute(db, attack.sql.replace("{tmp}", tmp_dir.as_posix()), policy, layers)
        changed = _digest(db) != before
        made_file = bool(attack.creates_file) and (tmp_dir / attack.creates_file).exists()
        return succeeded(attack, outcome, truth, policy, changed, made_file, base_db), outcome


def ablation(base_db: str | Path, policy: Policy | None = None, attacks: list[Attack] | None = None,
             configurations: dict[str, Layers] | None = None) -> dict[str, dict[str, bool]]:
    """{configuration name: {attack name: attack succeeded}}"""
    policy = policy or Policy.for_database(base_db)
    truth = read_truth(base_db)
    return {
        name: {a.name: run_attack(a, base_db, policy, layers, truth)[0] for a in (attacks or ATTACKS)}
        for name, layers in (configurations or CONFIGURATIONS).items()
    }


def render_ablation(results: dict[str, dict[str, bool]], attacks: list[Attack] | None = None) -> str:
    attacks = attacks or ATTACKS
    names = list(results)
    categories = list(dict.fromkeys(a.category for a in attacks))
    lines = ["Attacks that succeeded, out of those attempted, by guardrail configuration:", "",
             "| Category (attacks) | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for category in categories:
        group = [a for a in attacks if a.category == category]
        cells = [f"{sum(results[n][a.name] for a in group)}/{len(group)}" for n in names]
        lines.append(f"| {category} ({len(group)}) | " + " | ".join(cells) + " |")
    totals = [f"**{sum(results[n].values())}/{len(attacks)}**" for n in names]
    lines.append("| **All** | " + " | ".join(totals) + " |")
    return "\n".join(lines)
