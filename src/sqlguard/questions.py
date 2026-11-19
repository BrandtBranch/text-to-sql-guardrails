"""Accuracy test: questions with reference SQL, scored by comparing query results, not SQL text.

Two queries are equivalent if they return the same rows. A model is free to write the query differently,
return the columns in another order, or add columns, as long as the reference answer is in there.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Question:
    id: str
    level: str  # easy | medium | hard
    text: str
    gold_sql: str

    @property
    def ordered(self) -> bool:
        return bool(re.search(r"\border\s+by\b", self.gold_sql, re.IGNORECASE))


QUESTIONS: list[Question] = [
    Question("E1", "easy", "How many employees are there?", "SELECT COUNT(*) FROM employees"),
    Question("E2", "easy", "How many projects have status 'active'?", "SELECT COUNT(*) FROM projects WHERE status = 'active'"),
    Question("E3", "easy", "List the names of all clients in Denmark in alphabetical order.", "SELECT name FROM clients WHERE country = 'Denmark' ORDER BY name"),
    Question("E4", "easy", "What is the total budget across all projects?", "SELECT SUM(budget) FROM projects"),
    Question("E5", "easy", "How many invoices are overdue?", "SELECT COUNT(*) FROM invoices WHERE status = 'overdue'"),
    Question("E6", "easy", "How many expenses are in the Travel category?", "SELECT COUNT(*) FROM expenses WHERE category = 'Travel'"),
    Question("E7", "easy", "How many employees work in each office?", "SELECT office, COUNT(*) FROM employees GROUP BY office"),
    Question("E8", "easy", "What is the largest single expense amount?", "SELECT MAX(amount) FROM expenses"),
    Question("M1", "medium", "Which client has the highest total project budget? Give the client name.",
             "SELECT c.name FROM clients c JOIN projects p ON p.client_id = c.id GROUP BY c.id ORDER BY SUM(p.budget) DESC LIMIT 1"),
    Question("M2", "medium", "What is the total invoiced amount per client, highest first? Include every client that has been invoiced.",
             "SELECT c.name, SUM(i.amount) FROM invoices i JOIN projects p ON p.id = i.project_id JOIN clients c ON c.id = p.client_id GROUP BY c.id ORDER BY SUM(i.amount) DESC"),
    Question("M3", "medium", "How many hours have been logged in total on project 1?", "SELECT SUM(hours) FROM timesheets WHERE project_id = 1"),
    Question("M4", "medium", "Which 5 employees have logged the most billable hours? Give their names and the hours.",
             "SELECT e.name, SUM(t.hours) FROM timesheets t JOIN employees e ON e.id = t.employee_id WHERE t.billable = 1 GROUP BY e.id ORDER BY SUM(t.hours) DESC LIMIT 5"),
    Question("M5", "medium", "What is the total amount of expenses per category?", "SELECT category, SUM(amount) FROM expenses GROUP BY category"),
    Question("M6", "medium", "Which employees lead more than 3 projects? Give their names.",
             "SELECT e.name FROM employees e JOIN projects p ON p.lead_id = e.id GROUP BY e.id HAVING COUNT(*) > 3"),
    Question("M7", "medium", "What is the average amount of the paid invoices?", "SELECT AVG(amount) FROM invoices WHERE status = 'paid'"),
    Question("M8", "medium", "Which clients have no overdue invoices? Give the client names.",
             "SELECT name FROM clients WHERE id NOT IN (SELECT p.client_id FROM projects p JOIN invoices i ON i.project_id = p.id WHERE i.status = 'overdue')"),
    Question("M9", "medium", "How many different employees have logged time on active projects?",
             "SELECT COUNT(DISTINCT t.employee_id) FROM timesheets t JOIN projects p ON p.id = t.project_id WHERE p.status = 'active'"),
    Question("M10", "medium", "What is the total unpaid invoice amount (invoices that are not paid) per client country?",
             "SELECT c.country, SUM(i.amount) FROM invoices i JOIN projects p ON p.id = i.project_id JOIN clients c ON c.id = p.client_id WHERE i.status != 'paid' GROUP BY c.country"),
    Question("H1", "hard", "Which projects have been invoiced for more than their budget? Give the project name, total invoiced and budget.",
             "SELECT p.name, SUM(i.amount), p.budget FROM projects p JOIN invoices i ON i.project_id = p.id GROUP BY p.id HAVING SUM(i.amount) > p.budget"),
    Question("H2", "hard", "How many invoices were issued in each year?", "SELECT strftime('%Y', issue_date), COUNT(*) FROM invoices GROUP BY 1"),
    Question("H3", "hard", "Which employee logged the most hours in March 2026? Give the name.",
             "SELECT e.name FROM timesheets t JOIN employees e ON e.id = t.employee_id WHERE t.work_date LIKE '2026-03%' GROUP BY e.id ORDER BY SUM(t.hours) DESC LIMIT 1"),
    Question("H4", "hard", "What percentage of all logged hours are billable? Round to 1 decimal place.",
             "SELECT ROUND(100.0 * SUM(CASE WHEN billable = 1 THEN hours ELSE 0 END) / SUM(hours), 1) FROM timesheets"),
    Question("H5", "hard", "On average, how many days pass between the issue date and the paid date of paid invoices? Round to 1 decimal place.",
             "SELECT ROUND(AVG(julianday(paid_date) - julianday(issue_date)), 1) FROM invoices WHERE status = 'paid'"),
    Question("H6", "hard", "Which clients have at least one overdue invoice? Give the client names.",
             "SELECT DISTINCT c.name FROM clients c JOIN projects p ON p.client_id = c.id JOIN invoices i ON i.project_id = p.id WHERE i.status = 'overdue'"),
    Question("H7", "hard", "For each project lead, what is the combined budget of the projects they lead? Show the top 3 leads by name.",
             "SELECT e.name, SUM(p.budget) FROM projects p JOIN employees e ON e.id = p.lead_id GROUP BY e.id ORDER BY SUM(p.budget) DESC LIMIT 3"),
    Question("H8", "hard", "Which employee has the highest total expenses? Give the name and the total.",
             "SELECT e.name, SUM(x.amount) FROM expenses x JOIN employees e ON e.id = x.employee_id GROUP BY e.id ORDER BY SUM(x.amount) DESC LIMIT 1"),
    Question("H9", "hard", "Which month had the highest total invoiced amount? Give the month as YYYY-MM and the total.",
             "SELECT strftime('%Y-%m', issue_date), SUM(amount) FROM invoices GROUP BY 1 ORDER BY SUM(amount) DESC LIMIT 1"),
    Question("H10", "hard", "How many projects have both an overdue invoice and an expense above 4000?",
             "SELECT COUNT(*) FROM projects p WHERE EXISTS (SELECT 1 FROM invoices i WHERE i.project_id = p.id AND i.status = 'overdue') AND EXISTS (SELECT 1 FROM expenses x WHERE x.project_id = p.id AND x.amount > 4000)"),
]


def _norm(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 2)
    if isinstance(value, str):
        return value.strip()
    return value


def _rows(rows: list[tuple]) -> list[tuple]:
    return [tuple(_norm(v) for v in row) for row in rows]


def _key(row: tuple) -> tuple:
    return tuple((type(v).__name__ if v is None else "", str(v)) for v in row)


def same_result(gold: list[tuple], got: list[tuple], ordered: bool) -> bool:
    """True if `got` contains the gold answer. Extra columns and a different column order are allowed."""
    gold, got = _rows(gold), _rows(got)
    if len(gold) != len(got):
        return False
    if not gold:
        return True
    width = len(gold[0])
    if not got or len(got[0]) < width or len(got[0]) > width + 4:
        return False
    for picked in itertools.permutations(range(len(got[0])), width):
        candidate = [tuple(row[i] for i in picked) for row in got]
        if ordered:
            if candidate == gold:
                return True
        elif sorted(candidate, key=_key) == sorted(gold, key=_key):
            return True
    return False
