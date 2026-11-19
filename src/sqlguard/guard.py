"""Layer 1: validate a query by parsing it, before the database sees it.

The parser layer is the most readable guardrail and the easiest to get subtly wrong, because the parser can read a
query differently from the database. Two defences against that: the query that is executed is the parser's own
re-serialisation of the validated tree, not the original string, and the sandbox adds layers that do not depend on parsing.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from .db import BUSINESS_TABLES

DEFAULT_DENIED_FUNCTIONS = frozenset({"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "zeroblob", "randomblob"})
_COMMENT_ONLY = tuple(getattr(exp, n) for n in ("Semicolon",) if hasattr(exp, n)) or (type(None),)
_WRITE_NODES = tuple(getattr(exp, n) for n in ("Insert", "Update", "Delete", "Drop", "Create", "Alter", "Command", "Pragma", "Attach", "Detach", "Merge") if hasattr(exp, n))


@dataclass(frozen=True)
class Policy:
    allowed_tables: frozenset[str] = frozenset(BUSINESS_TABLES)
    denied_columns: frozenset[str] = frozenset({"salary", "email"})
    table_columns: Mapping[str, frozenset[str]] = field(default_factory=dict)  # lets us see what `SELECT *` would expand to
    denied_functions: frozenset[str] = DEFAULT_DENIED_FUNCTIONS
    max_rows: int = 200
    max_joins: int = 4
    max_sql_chars: int = 4000
    allow_recursive: bool = False
    aggregate_columns: frozenset[str] = frozenset({"salary"})  # denied as individual values, but readable as AVG or SUM over big groups
    aggregate_dimensions: frozenset[str] = frozenset({"role", "office"})  # the only columns such a query may group or filter by
    aggregate_table: str = "employees"
    min_group_size: int = 5  # groups smaller than this are withheld
    timeout: float = 1.0  # seconds a query may run
    hard_timeout: float = 3.0  # absolute cap used when the timeout layer is off, so a test can never hang

    @classmethod
    def for_database(cls, path: str | Path, **overrides) -> "Policy":
        """Build a policy from a database, recording the columns of every allowed table."""
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            allowed = overrides.pop("allowed_tables", frozenset(BUSINESS_TABLES))
            columns = {t: frozenset(r[1].lower() for r in conn.execute(f"PRAGMA table_info({t})")) for t in allowed}
        finally:
            conn.close()
        return cls(allowed_tables=frozenset(allowed), table_columns=columns, **overrides)


class GuardViolation(Exception):
    """A query was rejected. `code` is stable and machine-readable; the message is for people."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AggregatePlan:
    """What the sandbox must check before a statistics query on a restricted column may run."""

    ids_sql: str  # one row per group that will be released, holding the employee ids behind it
    grouped: bool
    groups_sql: str | None  # counts every group, so the answer can say how many were withheld


@dataclass(frozen=True)
class Validated:
    sql: str  # the re-serialised query to execute
    tables: frozenset[str]
    aggregate: AggregatePlan | None = None


_COMPARISONS = tuple(getattr(exp, n) for n in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE") if hasattr(exp, n))


def _relates_two_tables(condition: exp.Expression | None) -> bool:
    """True if some comparison in the join condition involves columns from at least two different tables.

    This catches `ON 1=1` and `ON a.id >= 0 AND b.id >= 0`. It cannot catch `ON a.id + b.id > 0`, which
    mentions both tables and still matches almost every pair of rows. Telling those apart needs the query's
    meaning, not its syntax, which is why the sandbox also enforces a time limit.
    """
    if condition is None:
        return False
    for comparison in condition.find_all(*_COMPARISONS):
        columns = list(comparison.find_all(exp.Column))
        qualifiers = {c.table.lower() for c in columns}
        # two columns that are not all from one named table (unqualified columns could belong to either side)
        if len(columns) >= 2 and (len(qualifiers) >= 2 or qualifiers == {""}):
            return True
    return False


def _plan_aggregate(tree: exp.Expression, tables: set[str], protected: list[exp.Expression], policy: Policy) -> tuple[exp.Expression, AggregatePlan]:
    """Check that a query touching a restricted column is a plain statistic, and work out how to enforce the group size.

    Allowed shape: one SELECT on one table, no joins, subqueries, window functions or FILTER clauses (a FILTER narrows the
    people behind an average in a way the group-size check cannot see); the restricted column only as
    AVG or SUM; everything else limited to the allowed dimensions. Groups under the minimum size are removed by an extra
    HAVING clause, and the sandbox checks the rest with the id lists in the plan.
    """
    k = policy.min_group_size
    if (not isinstance(tree, exp.Select) or len(list(tree.find_all(exp.Select))) != 1 or tree.find(exp.With)
            or tree.find(exp.Join) or tree.find(exp.Window) or tree.find(exp.Filter) or tables != {policy.aggregate_table}):
        raise GuardViolation("aggregate_shape", f"statistics on restricted columns must be one plain SELECT on {policy.aggregate_table}, with no joins, subqueries, window functions or FILTER clauses")
    dimensions = sorted(policy.aggregate_dimensions)
    aliases = {a.alias.lower() for a in tree.expressions if isinstance(a, exp.Alias)}
    for column in tree.find_all(exp.Column):
        if any(column.parent is node for node in protected):
            continue
        if column.name.lower() not in policy.aggregate_dimensions | aliases:
            raise GuardViolation("aggregate_dimension", f"statistics on restricted columns can only filter or group by {dimensions}, not {column.name.lower()!r}")
    group = tree.args.get("group")
    if group and not all(isinstance(e, exp.Column) and e.name.lower() in policy.aggregate_dimensions for e in group.expressions):
        raise GuardViolation("aggregate_dimension", f"GROUP BY can only use {dimensions}")
    where = tree.args.get("where")
    where_sql = where.sql(dialect="sqlite") if where else ""
    table = policy.aggregate_table
    if group:
        group_sql = group.sql(dialect="sqlite")
        plan = AggregatePlan(f"SELECT GROUP_CONCAT(id) FROM {table} {where_sql} {group_sql} HAVING COUNT(*) >= {k}", True,
                             f"SELECT COUNT(*) FROM (SELECT 1 FROM {table} {where_sql} {group_sql})")
        tree = tree.having(f"COUNT(*) >= {k}", append=True, dialect="sqlite")
    else:
        plan = AggregatePlan(f"SELECT GROUP_CONCAT(id) FROM {table} {where_sql}", False, None)
    return tree, plan


def validate(sql: str, policy: Policy) -> Validated:
    if not sql or not sql.strip():
        raise GuardViolation("empty", "the query is empty")
    if len(sql) > policy.max_sql_chars:
        raise GuardViolation("too_long", f"the query is longer than {policy.max_sql_chars} characters")
    try:
        # A trailing comment parses as a comment-only "statement". It carries no query, and comments are dropped from what is executed.
        statements = [s for s in sqlglot.parse(sql, read="sqlite") if s is not None and not isinstance(s, _COMMENT_ONLY)]
    except SqlglotError as exc:
        raise GuardViolation("unparseable", f"the query could not be parsed: {str(exc)[:120]}") from exc
    if len(statements) != 1:
        raise GuardViolation("multiple_statements", f"expected one statement, found {len(statements)}")
    tree = statements[0]

    if _WRITE_NODES and any(tree.find(node) for node in _WRITE_NODES) or not isinstance(tree, exp.Query):
        raise GuardViolation("not_read_only", "only plain SELECT queries are allowed")

    ctes = {cte.alias.lower() for cte in tree.find_all(exp.CTE)}
    tables = set()
    for table in tree.find_all(exp.Table):
        name = table.name.lower()
        if table.db or table.catalog:
            raise GuardViolation("schema_qualified", "schema-qualified table names are not allowed")
        if name in ctes:
            continue
        if name not in policy.allowed_tables:
            raise GuardViolation("table_not_allowed", f"table {name or '(table-valued function)'!r} is not available")
        tables.add(name)

    protected: list[exp.Expression] = []  # the AVG or SUM nodes that wrap a restricted column
    for column in tree.find_all(exp.Column):
        name = column.name.lower()
        if name in policy.denied_columns:
            if name in policy.aggregate_columns and isinstance(column.parent, (exp.Avg, exp.Sum)) and column.parent.this is column:
                protected.append(column.parent)
                continue
            if name in policy.aggregate_columns:
                raise GuardViolation("denied_column", f"column {name!r} can only be used as AVG or SUM, over groups of at least {policy.min_group_size} employees")
            raise GuardViolation("denied_column", f"column {name!r} is not available")
    sensitive = {t for t in tables if policy.table_columns.get(t, frozenset()) & policy.denied_columns}
    for star in tree.find_all(exp.Star):
        if isinstance(star.parent, exp.Count):
            continue
        if sensitive:
            raise GuardViolation("star_over_sensitive_table", f"SELECT * would include restricted columns from {sorted(sensitive)}; name the columns you need")

    for func in tree.find_all(exp.Func):
        name = (func.name if isinstance(func, exp.Anonymous) else func.sql_name()).lower()
        if name in policy.denied_functions:
            raise GuardViolation("denied_function", f"function {name!r} is not allowed")

    if not policy.allow_recursive and any(w.args.get("recursive") for w in tree.find_all(exp.With)):
        raise GuardViolation("recursive_query", "recursive queries are not allowed")

    joins = list(tree.find_all(exp.Join))
    if len(joins) > policy.max_joins:
        raise GuardViolation("too_many_joins", f"{len(joins)} joins; the limit is {policy.max_joins}")
    for join in joins:
        if join.args.get("using") or join.args.get("method"):
            continue
        if not _relates_two_tables(join.args.get("on")):
            raise GuardViolation("cartesian_product", "every join needs a condition that relates the two tables")

    plan = None
    if protected:
        tree, plan = _plan_aggregate(tree, tables, protected, policy)
    return Validated(sql=tree.sql(dialect="sqlite", comments=False), tables=frozenset(tables), aggregate=plan)
