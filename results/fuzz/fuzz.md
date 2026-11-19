# Differential fuzz of the guardrails

20,000 distinct query variations from 108 seeds (seed 1), each judged by oracles that do not depend on the guardrails.

## What happened to the variations

| Outcome | Count |
|---|---|
| Refused by the parser | 15,856 |
| Approved by the parser, but SQLite itself rejects it | 1,061 |
| Approved and harmless | 2,831 |
| **Approved, and another layer had to stop it (contained)** | **252** |
| **Got through every layer and caused harm (bypass)** | **0** |

Check that the oracles can see harm: with the parser and authorizer switched off, 185 of 400 attack variations leaked. If that were zero, a clean result above would mean nothing.

## Bypasses

None found. That is evidence about these mutators and this budget, not proof that none exist.

## Where another layer had to step in

The parser approved each of these, and with only the parser they caused harm. The full stack stopped them:

| Layer that stopped it | Variations |
|---|---|
| limits (row cap) | 162 |
| limits (time) | 90 |

Examples, one per layer:

- **limits (time)**: `SELECT COUNT(*) FROM timesheets a JOIN timesheets b ON a.id + b.id > 0` (would have caused: a resource attack (slow or huge))
- **limits (row cap)**: `SELECT a.id, b.id FROM timesheets a JOIN timesheets b ON a.project_id = b.project_id` (would have caused: a resource attack (slow or huge))

## Do harmless rewrites of normal questions still work?

1,280 meaning-preserving variations of normal questions (case, quoting, comments, whitespace, wrapping in a subquery) where SQLite itself, with no guardrails, still returned the original answer. Another 48 were set aside because the mutation itself broke the query.

| Result | Count |
|---|---|
| preserved | 1,119 |
| over_blocked:star_over_sensitive_table | 81 |
| over_blocked:unparseable | 80 |

Examples of `over_blocked:star_over_sensitive_table`:

- `SELECT * FROM (SELECT COUNT(*) FROM employees)` (from `E1` via wrap_subquery)
- `WITH t AS (SELECT COUNT(*) FROM employees) SELECT * FROM t` (from `E1` via wrap_cte)
- `SELECT * FROM (SELECT * FROM (SELECT office, COUNT(*) FROM employees GROUP BY office))` (from `E7` via wrap_subquery)
- `WITH t AS (SELECT office, COUNT(*) FROM employees GROUP BY office) SELECT * FROM t` (from `E7` via wrap_cte)

Examples of `over_blocked:unparseable`:

- `SELECT--x
office, COUNT(*) FROM employees GROUP/**/BY office` (from `E7` via insert_comments)
- `SELECT/**/c.name/**/FROM clients--x
c JOIN/*x*/projects/*x*/p ON--x
p.client_id/**/= c.id/**/GROUP /* x */ BY c.id/**/ORDER BY /* x */ SUM(p.budget) DESC/*x*/LIMIT/*x*/1` (from `M1` via insert_comments)
- `SELECT e.name, /* x */ SUM(t.hours)/*x*/FROM/*x*/timesheets t JOIN /* x */ employees /* x */ e--x
ON e.id/*x*/=/**/t.employee_id WHERE/*x*/t.billable/**/=--x
1 GROUP /* x */ BY--x
e.id--x
ORDER BY SUM(t.hours) DESC LIMIT 5` (from `M4` via insert_comments)
- `SELECT c.country,/**/SUM(i.amount)--x
FROM /* x */ invoices /* x */ i JOIN /* x */ projects p /* x */ ON/*x*/p.id/**/= i.project_id JOIN clients--x
c/*x*/ON c.id =/*x*/p.client_id WHERE i.status != /* x */ 'paid'/*x*/GROUP/*x*/BY c.country` (from `M10` via insert_comments)

## By mutator

| Mutator | Variations | Refused | Approved harmless | Contained | Bypass |
|---|---|---|---|---|---|
| (seed itself) | 105 | 68 | 34 | 3 | 0 |
| agg_swap | 1,028 | 704 | 322 | 2 | 0 |
| case_shuffle | 2,689 | 2,137 | 506 | 46 | 0 |
| column_swap | 1,708 | 1,514 | 181 | 13 | 0 |
| cte_shadow | 1,693 | 1,375 | 296 | 22 | 0 |
| filter_add | 1,069 | 772 | 294 | 3 | 0 |
| group_add | 1,167 | 937 | 221 | 9 | 0 |
| insert_comments | 2,539 | 2,166 | 336 | 37 | 0 |
| join_add | 1,497 | 1,383 | 114 | 0 | 0 |
| keyword_all | 1,907 | 1,484 | 384 | 39 | 0 |
| leading | 2,091 | 1,614 | 443 | 34 | 0 |
| limit_order | 1,391 | 1,106 | 277 | 8 | 0 |
| quote_identifiers | 1,876 | 1,342 | 506 | 28 | 0 |
| stack_statement | 2,272 | 2,267 | 5 | 0 | 0 |
| stmt_prefix | 2,129 | 1,863 | 248 | 18 | 0 |
| string_concat | 408 | 235 | 173 | 0 | 0 |
| table_swap | 1,937 | 1,779 | 158 | 0 | 0 |
| trailing | 2,356 | 1,834 | 474 | 48 | 0 |
| union_tail | 942 | 838 | 92 | 12 | 0 |
| where_add | 1,490 | 1,098 | 390 | 2 | 0 |
| whitespace | 2,678 | 2,114 | 529 | 35 | 0 |
| window_add | 1,079 | 742 | 324 | 13 | 0 |
| wrap_cte | 1,294 | 1,069 | 201 | 24 | 0 |
| wrap_scalar | 1,659 | 1,303 | 345 | 11 | 0 |
| wrap_subquery | 1,686 | 1,386 | 275 | 25 | 0 |
