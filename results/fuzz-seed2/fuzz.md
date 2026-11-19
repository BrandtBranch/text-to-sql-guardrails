# Differential fuzz of the guardrails

20,000 distinct query variations from 108 seeds (seed 2), each judged by oracles that do not depend on the guardrails.

## What happened to the variations

| Outcome | Count |
|---|---|
| Refused by the parser | 15,977 |
| Approved by the parser, but SQLite itself rejects it | 1,042 |
| Approved and harmless | 2,737 |
| **Approved, and another layer had to stop it (contained)** | **244** |
| **Got through every layer and caused harm (bypass)** | **0** |

Check that the oracles can see harm: with the parser and authorizer switched off, 184 of 400 attack variations leaked. If that were zero, a clean result above would mean nothing.

## Bypasses

None found. That is evidence about these mutators and this budget, not proof that none exist.

## Where another layer had to step in

The parser approved each of these, and with only the parser they caused harm. The full stack stopped them:

| Layer that stopped it | Variations |
|---|---|
| limits (row cap) | 167 |
| limits (time) | 77 |

Examples, one per layer:

- **limits (time)**: `SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id + b.id > 0` (would have caused: a resource attack (slow or huge))
- **limits (row cap)**: `SELECT a.id, b.id FROM timesheets a JOIN timesheets b ON a.project_id = b.project_id` (would have caused: a resource attack (slow or huge))

## Do harmless rewrites of normal questions still work?

1,252 meaning-preserving variations of normal questions (case, quoting, comments, whitespace, wrapping in a subquery) where SQLite itself, with no guardrails, still returned the original answer. Another 28 were set aside because the mutation itself broke the query.

| Result | Count |
|---|---|
| preserved | 1,084 |
| over_blocked:star_over_sensitive_table | 99 |
| over_blocked:unparseable | 69 |

Examples of `over_blocked:star_over_sensitive_table`:

- `SELECT * FROM (SELECT * FROM (SELECT COUNT(*) FROM employees))` (from `E1` via wrap_subquery)
- `WITH t AS (SELECT COUNT(*) FROM employees) SELECT * FROM t` (from `E1` via wrap_cte)
- `SELECT * FROM (SELECT office, COUNT(*) FROM employees GROUP BY office) AS t` (from `E7` via wrap_subquery)
- `WITH t AS (SELECT office, COUNT(*) FROM employees GROUP BY office) SELECT * FROM t` (from `E7` via wrap_cte)

Examples of `over_blocked:unparseable`:

- `SELECT c.name/**/FROM /* x */ clients /* x */ c JOIN projects p--x
ON p.client_id/*x*/=/*x*/c.id GROUP/**/BY c.id /* x */ ORDER BY/*x*/SUM(p.budget) /* x */ DESC LIMIT 1` (from `M1` via insert_comments)
- `SELECT /* x */ c.name,/*x*/SUM(i.amount) FROM invoices i--x
JOIN projects--x
p /* x */ ON p.id =/*x*/i.project_id JOIN clients--x
c ON c.id /* x */ = p.client_id GROUP /* x */ BY c.id ORDER/**/BY/**/SUM(i.amount) /* x */ DESC` (from `M2` via insert_comments)
- `SELECT--x
e.name, SUM(t.hours) FROM--x
timesheets--x
t JOIN employees/**/e ON--x
e.id =/**/t.employee_id WHERE t.billable = 1/*x*/GROUP/**/BY e.id ORDER/*x*/BY SUM(t.hours) DESC/**/LIMIT--x
5` (from `M4` via insert_comments)
- `SELECT e.name FROM /* x */ timesheets t JOIN employees--x
e ON/**/e.id =--x
t.employee_id WHERE/*x*/t.work_date/*x*/LIKE--x
'2026-03%' GROUP BY e.id/*x*/ORDER/*x*/BY SUM(t.hours)/*x*/DESC LIMIT 1` (from `H3` via insert_comments)

## By mutator

| Mutator | Variations | Refused | Approved harmless | Contained | Bypass |
|---|---|---|---|---|---|
| (seed itself) | 105 | 68 | 34 | 3 | 0 |
| agg_swap | 1,083 | 743 | 337 | 3 | 0 |
| case_shuffle | 2,661 | 2,137 | 479 | 45 | 0 |
| column_swap | 1,620 | 1,454 | 158 | 8 | 0 |
| cte_shadow | 1,706 | 1,377 | 311 | 18 | 0 |
| filter_add | 1,041 | 752 | 288 | 1 | 0 |
| group_add | 1,257 | 1,037 | 215 | 5 | 0 |
| insert_comments | 2,487 | 2,097 | 357 | 33 | 0 |
| join_add | 1,468 | 1,364 | 103 | 1 | 0 |
| keyword_all | 1,844 | 1,452 | 369 | 23 | 0 |
| leading | 2,158 | 1,668 | 457 | 33 | 0 |
| limit_order | 1,462 | 1,179 | 276 | 7 | 0 |
| quote_identifiers | 1,881 | 1,380 | 469 | 32 | 0 |
| stack_statement | 2,208 | 2,197 | 10 | 1 | 0 |
| stmt_prefix | 2,176 | 1,935 | 225 | 16 | 0 |
| string_concat | 426 | 227 | 199 | 0 | 0 |
| table_swap | 2,006 | 1,868 | 137 | 1 | 0 |
| trailing | 2,376 | 1,865 | 473 | 38 | 0 |
| union_tail | 988 | 894 | 81 | 13 | 0 |
| where_add | 1,518 | 1,161 | 354 | 3 | 0 |
| whitespace | 2,581 | 2,070 | 473 | 38 | 0 |
| window_add | 1,101 | 742 | 339 | 20 | 0 |
| wrap_cte | 1,295 | 1,073 | 197 | 25 | 0 |
| wrap_scalar | 1,655 | 1,275 | 375 | 5 | 0 |
| wrap_subquery | 1,669 | 1,344 | 301 | 24 | 0 |
