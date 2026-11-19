"""A differencing attack on salary statistics, and whether the audit layer stops it.

Every query below is individually allowed: an average of salary over a role, a group of five or more people.
But the average for a role, minus the average for the same role excluding one office, isolates the one person who
is in that office. The minimum group size cannot see this, because it looks at one query at a time.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .guard import Policy
from .sandbox import AuditLog, Layers, execute


@dataclass
class DifferencingResult:
    target_id: int
    role: str
    office: str
    true_salary: int
    recovered: float | None  # None when the attack was stopped
    stopped_by: str | None  # the guardrail code that refused one of the two queries

    @property
    def succeeded(self) -> bool:
        return self.recovered is not None and abs(self.recovered - self.true_salary) < 1e-6


def find_targets(db_path: str | Path, k: int) -> list[tuple[int, str, str, int]]:
    """(employee id, role, office, salary) of everyone who is alone in their role and office, in a role of at least k + 1 people."""
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        sizes = dict(conn.execute("SELECT role, COUNT(*) FROM employees GROUP BY role"))
        cells = {(r, o): n for r, o, n in conn.execute("SELECT role, office, COUNT(*) FROM employees GROUP BY role, office")}
        return [(i, r, o, s) for i, r, o, s in conn.execute("SELECT id, role, office, salary FROM employees")
                if cells[(r, o)] == 1 and sizes[r] >= k + 1]
    finally:
        conn.close()


def differencing_attack(db_path: str | Path, policy: Policy, layers: Layers = Layers(), use_audit: bool = False) -> list[DifferencingResult]:
    """Try to recover every findable salary using only two allowed average queries per person."""
    results = []
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        for target, role, office, salary in find_targets(db_path, policy.min_group_size):
            audit = AuditLog() if use_audit else None  # one session per target, so one target's queries do not affect another's
            n = conn.execute("SELECT COUNT(*) FROM employees WHERE role = ?", (role,)).fetchone()[0]
            whole = execute(db_path, f"SELECT AVG(salary) FROM employees WHERE role = '{role}'", policy, layers, audit)
            without = execute(db_path, f"SELECT AVG(salary) FROM employees WHERE role = '{role}' AND office <> '{office}'", policy, layers, audit)
            if whole.status == without.status == "ok":
                recovered = n * whole.rows[0][0] - (n - 1) * without.rows[0][0]
                results.append(DifferencingResult(target, role, office, salary, recovered, None))
            else:
                stopped = next(o.code for o in (whole, without) if o.status != "ok")
                results.append(DifferencingResult(target, role, office, salary, None, stopped))
    finally:
        conn.close()
    return results


def render(results_without: list[DifferencingResult], results_with: list[DifferencingResult]) -> str:
    lines = ["Differencing attack: two allowed average queries per person, subtracted.", "",
             "| Employee | Role, office | True salary | Recovered without audit | With audit |", "|---|---|---|---|---|"]
    for plain, audited in zip(results_without, results_with):
        got = f"{plain.recovered:,.0f}" if plain.recovered is not None else f"stopped ({plain.stopped_by})"
        lines.append(f"| {plain.target_id} | {plain.role}, {plain.office} | {plain.true_salary:,} | {got} | "
                     f"{'recovered' if audited.succeeded else 'stopped (' + str(audited.stopped_by) + ')'} |")
    lines += ["", f"Recovered exactly without the audit: {sum(r.succeeded for r in results_without)} of {len(results_without)}. "
                  f"With the audit: {sum(r.succeeded for r in results_with)} of {len(results_with)}."]
    return "\n".join(lines)
