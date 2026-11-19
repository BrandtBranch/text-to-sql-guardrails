"""Layers 2 to 5, enforced around the database, plus the function that runs a query through every layer.

  parser      validate() from guard.py: reject before execution
  readonly    open the file read-only and set query_only: the engine refuses writes whatever the SQL says
  authorizer  a SQLite authorizer callback: the engine asks permission for every table, column and function it touches
  limits      a wall-clock timeout and a row cap
  audit       overlap control across the queries of one session, which stops a differencing attack on statistics

Each layer can be switched off independently, which is what the ablation in attacks.py needs.

Restricted columns such as salary are denied outright, with one exception: a statistics query that the parser has
approved (AVG or SUM over role or office, with groups under the minimum size removed). For that one statement the
authorizer is told it may read the column, so the engine-level default stays "deny" for everything else.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .guard import AggregatePlan, GuardViolation, Policy, validate

# SQLite's authorizer action codes. Older Pythons do not expose every constant, so fall back to the documented values.
_SELECT, _READ, _FUNCTION, _RECURSIVE = (getattr(sqlite3, name, code) for name, code in
                                         (("SQLITE_SELECT", 21), ("SQLITE_READ", 20), ("SQLITE_FUNCTION", 31), ("SQLITE_RECURSIVE", 33)))
_UNPROTECTED_ROW_CAP = 20_000  # so a test harness never holds millions of rows when the row cap layer is off


@dataclass(frozen=True)
class Layers:
    parser: bool = True
    readonly: bool = True
    authorizer: bool = True
    limits: bool = True
    audit: bool = True

    @classmethod
    def none(cls) -> "Layers":
        return cls(False, False, False, False, False)

    def label(self) -> str:
        on = [n for n in ("parser", "readonly", "authorizer", "limits", "audit") if getattr(self, n)]
        return "+".join(on) or "none"


@dataclass
class AuditLog:
    """Remembers which employees stood behind every statistic released in one session.

    A single average over five or more people is safe enough. Two averages whose groups differ by one person are not:
    the difference reveals that person's pay. So a new group is refused if it differs from an earlier one by fewer
    than `k` people, but is not identical to it. This is overlap control. It stops the simple version of the attack,
    not every version, because combining three or more queries can still isolate someone.
    """

    released: list[frozenset[int]] = field(default_factory=list)

    def conflict(self, groups: list[frozenset[int]], k: int) -> str | None:
        for group in groups:
            for earlier in self.released:
                difference = len(group ^ earlier)
                if 0 < difference < k:
                    return (f"this result differs from an earlier one by only {difference} employee(s), "
                            f"so comparing the two would reveal individual pay")
        return None

    def record(self, groups: list[frozenset[int]]) -> None:
        self.released.extend(g for g in groups if g not in self.released)


@dataclass
class Outcome:
    status: str  # ok | blocked | error | timeout
    columns: list[str] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    truncated: bool = False
    elapsed: float = 0.0
    code: str | None = None  # which guardrail stopped it, or the kind of error
    detail: str = ""
    executed_sql: str = ""
    withheld: int = 0  # groups removed because they were smaller than the minimum size


def _denied_by_authorizer(message: str) -> bool:
    """SQLite words a denial either 'not authorized' or 'access to <table>.<column> is prohibited'."""
    text = message.lower()
    return "not authorized" in text or "prohibited" in text


def make_authorizer(policy: Policy, unlocked: frozenset[str] = frozenset()):
    """An authorizer that allows reads of permitted columns and permitted functions, and denies everything else.

    `unlocked` names restricted columns that this one statement may read, because the parser approved it as a statistic.
    """
    def authorize(action, arg1, arg2, db_name, source):
        if action == _SELECT:
            return sqlite3.SQLITE_OK
        if action == _READ:
            table, column = (arg1 or "").lower(), (arg2 or "").lower()
            if table not in policy.allowed_tables or (column in policy.denied_columns and column not in unlocked):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action == _FUNCTION:
            return sqlite3.SQLITE_DENY if (arg2 or "").lower() in policy.denied_functions else sqlite3.SQLITE_OK
        if action == _RECURSIVE:
            return sqlite3.SQLITE_OK if policy.allow_recursive else sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY  # writes, DDL, ATTACH, PRAGMA, transactions: nothing else is permitted

    return authorize


def _check_groups(conn: sqlite3.Connection, plan: AggregatePlan, policy: Policy, layers: Layers, audit: AuditLog | None):
    """Work out which groups a statistics query would release, and refuse it if any rule is broken.

    Returns (groups, withheld, refusal). `refusal` is an Outcome when the query must not run.
    """
    k = policy.min_group_size
    groups = [frozenset(int(i) for i in row[0].split(",")) for row in conn.execute(plan.ids_sql) if row[0]]
    if not plan.grouped and (not groups or len(groups[0]) < k):
        return groups, 0, Outcome("blocked", code="small_group", detail=f"this statistic would cover fewer than {k} employees, so it is withheld")
    if layers.audit and audit is not None:
        problem = audit.conflict(groups, k)
        if problem:
            return groups, 0, Outcome("blocked", code="overlap", detail=problem)
    withheld = (conn.execute(plan.groups_sql).fetchone()[0] - len(groups)) if plan.groups_sql else 0
    return groups, withheld, None


def execute(db_path: str | Path, sql: str, policy: Policy, layers: Layers = Layers(), audit: AuditLog | None = None) -> Outcome:
    """Run `sql` against the database through whichever layers are switched on."""
    to_run, plan = sql, None
    if layers.parser:
        try:
            validated = validate(sql, policy)
        except GuardViolation as violation:
            return Outcome("blocked", code=violation.code, detail=str(violation))
        to_run, plan = validated.sql, validated.aggregate  # execute what was validated, not what was typed

    mode = "ro" if layers.readonly else "rwc"
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode={mode}", uri=True, isolation_level=None)
    try:
        if layers.readonly:
            conn.execute("PRAGMA query_only = ON")
        if layers.authorizer:
            conn.set_authorizer(make_authorizer(policy, policy.aggregate_columns if plan else frozenset()))
        limit = policy.timeout if layers.limits else policy.hard_timeout
        deadline = time.monotonic() + limit
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)
        cap = policy.max_rows if layers.limits else _UNPROTECTED_ROW_CAP
        started = time.monotonic()
        try:
            groups, withheld = [], 0
            if plan:
                groups, withheld, refusal = _check_groups(conn, plan, policy, layers, audit)
                if refusal:
                    refusal.executed_sql = to_run
                    return refusal
            cursor = conn.execute(to_run)
            columns = [d[0] for d in cursor.description or []]
            rows = cursor.fetchmany(cap + 1)
        except sqlite3.OperationalError as exc:
            elapsed = time.monotonic() - started
            code = "timeout" if "interrupted" in str(exc).lower() else ("authorizer" if _denied_by_authorizer(str(exc)) else "error")
            return Outcome("timeout" if code == "timeout" else ("blocked" if code == "authorizer" else "error"),
                           code=code, detail=str(exc), elapsed=elapsed, executed_sql=to_run)
        except sqlite3.DatabaseError as exc:
            code = "authorizer" if _denied_by_authorizer(str(exc)) else "error"
            return Outcome("blocked" if code == "authorizer" else "error", code=code, detail=str(exc),
                           elapsed=time.monotonic() - started, executed_sql=to_run)
        except (sqlite3.Warning, sqlite3.ProgrammingError) as exc:
            return Outcome("error", code="error", detail=str(exc), elapsed=time.monotonic() - started, executed_sql=to_run)
        if plan and layers.audit and audit is not None:
            audit.record(groups)
        truncated = len(rows) > cap
        note = f"{withheld} group(s) with fewer than {policy.min_group_size} employees were withheld to protect individual pay" if withheld else ""
        return Outcome("ok", columns=columns, rows=[tuple(r) for r in rows[:cap]], truncated=truncated,
                       elapsed=time.monotonic() - started, executed_sql=to_run, withheld=withheld, detail=note)
    finally:
        conn.close()
