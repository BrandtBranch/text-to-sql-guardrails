import hashlib
import sqlite3

import pytest

from sqlguard.db import BUSINESS_TABLES, build_database
from sqlguard.guard import GuardViolation, Policy, validate
from sqlguard.sandbox import Layers, execute

LEGIT = [
    "SELECT status, COUNT(*) AS n FROM projects GROUP BY status ORDER BY n DESC",
    "SELECT c.name, SUM(i.amount) AS billed FROM invoices i JOIN projects p ON p.id = i.project_id JOIN clients c ON c.id = p.client_id GROUP BY c.name ORDER BY billed DESC",
    "SELECT COUNT(*) FROM employees",
    "SELECT office, COUNT(*) FROM employees GROUP BY office",
    "WITH big AS (SELECT id FROM projects WHERE budget > 500000) SELECT COUNT(*) FROM big",
    "SELECT e.name FROM employees e WHERE e.id IN (SELECT lead_id FROM projects)",
]


def blocked_code(sql, policy):
    with pytest.raises(GuardViolation) as info:
        validate(sql, policy)
    return info.value.code


def test_database_is_deterministic_and_contains_the_sensitive_parts(tmp_path):
    a, b = build_database(tmp_path / "a.db"), build_database(tmp_path / "b.db")
    assert hashlib.sha256(a.read_bytes()).digest() == hashlib.sha256(b.read_bytes()).digest()
    conn = sqlite3.connect(a)
    assert {t for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")} == set(BUSINESS_TABLES) | {"internal_api_keys"}
    assert conn.execute("SELECT COUNT(*) FROM clients WHERE notes LIKE '%ignore all previous instructions%'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM timesheets").fetchone()[0] > 10_000  # large enough that a cross join hurts


@pytest.mark.parametrize("sql", LEGIT)
def test_legitimate_queries_pass_every_layer_and_return_what_an_unprotected_run_returns(db, policy, sql):
    guarded = execute(db, sql, policy, Layers())
    assert guarded.status == "ok", guarded.detail
    assert guarded.rows == execute(db, sql, policy, Layers.none()).rows  # re-serialising the query does not change its meaning


@pytest.mark.parametrize("sql,code", [
    ("", "empty"),
    ("SELECT 1; SELECT 2", "multiple_statements"),
    ("DROP TABLE clients", "not_read_only"),
    ("UPDATE employees SET salary = 0", "not_read_only"),
    ("PRAGMA user_version = 1", "not_read_only"),
    ("ATTACH DATABASE 'x.db' AS x", "not_read_only"),
    ("SELECT name FROM sqlite_master", "table_not_allowed"),
    ("SELECT key FROM internal_api_keys", "table_not_allowed"),
    ("SELECT key FROM main.internal_api_keys", "schema_qualified"),
    ("SELECT name FROM pragma_table_info('employees')", "table_not_allowed"),
    ("SELECT salary FROM employees", "denied_column"),
    ('SELECT "SaLaRy" FROM [employees]', "denied_column"),
    ("SELECT * FROM employees", "star_over_sensitive_table"),
    ("SELECT e.* FROM employees e", "star_over_sensitive_table"),
    ("SELECT load_extension('x')", "denied_function"),
    ("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT n FROM r", "recursive_query"),
    ("SELECT COUNT(*) FROM timesheets a, timesheets b", "cartesian_product"),
    ("SELECT 1 FROM projects a JOIN projects b ON a.id=b.id JOIN projects c ON a.id=c.id JOIN projects d ON a.id=d.id JOIN projects e ON a.id=e.id JOIN projects f ON a.id=f.id", "too_many_joins"),
    ("SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON 1=1", "cartesian_product"),
    ("SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id >= 0 AND b.id >= 0", "cartesian_product"),
    ("SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id = a.id", "cartesian_product"),
    ("SELECT " + "1," * 3000 + "1", "too_long"),
])
def test_the_parser_layer_reports_a_specific_reason(policy, sql, code):
    assert blocked_code(sql, policy) == code


@pytest.mark.parametrize("sql", [
    "SELECT COUNT(*) FROM timesheets a JOIN projects b ON a.project_id = b.id",
    "SELECT COUNT(*) FROM timesheets JOIN projects ON project_id = projects.id",
    "SELECT COUNT(*) FROM timesheets JOIN projects ON timesheets.project_id = projects.id AND projects.status = 'active'",
    "SELECT COUNT(*) FROM timesheets JOIN projects USING (id)",
])
def test_real_joins_are_allowed_including_unqualified_columns(policy, sql):
    validate(sql, policy)


def test_the_parser_cannot_tell_a_disguised_cross_join_apart_by_syntax(policy):
    validate("SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id + b.id > 0", policy)  # mentions both tables, matches almost every pair


def test_count_star_and_star_over_a_safe_table_are_allowed(policy):
    validate("SELECT COUNT(*) FROM employees", policy)
    validate("SELECT * FROM clients", policy)


def test_the_validated_query_is_the_parsers_own_rendering_without_comments(policy):
    sql = validate("SELECT name /* sneaky */ FROM clients -- trailing", policy).sql
    assert "sneaky" not in sql and "trailing" not in sql


def test_authorizer_alone_stops_disguised_reads_the_parser_is_not_involved(db, policy):
    only_authorizer = Layers(parser=False, readonly=False, authorizer=True, limits=False)
    for sql in ('SELECT "SaLaRy" FROM [employees]', "SELECT key FROM internal_api_keys", "SELECT * FROM employees", "SELECT name FROM sqlite_master"):
        assert execute(db, sql, policy, only_authorizer).code == "authorizer", sql
    assert execute(db, "SELECT name FROM clients LIMIT 1", policy, only_authorizer).status == "ok"


def test_readonly_alone_stops_writes_but_not_reads(db, tmp_path, policy):
    import shutil

    copy = tmp_path / "copy.db"
    shutil.copy(db, copy)
    only_readonly = Layers(parser=False, readonly=True, authorizer=False, limits=False)
    assert execute(copy, "DELETE FROM invoices", policy, only_readonly).status == "error"
    assert sqlite3.connect(copy).execute("SELECT COUNT(*) FROM invoices").fetchone()[0] > 0
    assert execute(copy, "SELECT salary FROM employees LIMIT 1", policy, only_readonly).status == "ok"


def test_limits_cap_rows_and_abort_slow_queries(db, policy):
    capped = execute(db, "SELECT id FROM timesheets", policy, Layers(parser=False, readonly=False, authorizer=False, limits=True))
    assert capped.status == "ok" and len(capped.rows) == policy.max_rows and capped.truncated
    slow = Layers(parser=False, readonly=False, authorizer=False, limits=True)
    outcome = execute(db, "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT MAX(n) FROM r", policy, slow)
    assert outcome.status == "timeout" and policy.timeout <= outcome.elapsed < policy.timeout + 1


def test_a_policy_can_allow_what_the_default_forbids(db):
    relaxed = Policy.for_database(db, denied_columns=frozenset(), allow_recursive=True)
    assert validate("SELECT salary FROM employees", relaxed).sql
    assert validate("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < 5) SELECT n FROM r", relaxed).sql
