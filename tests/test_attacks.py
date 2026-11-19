import pytest

from sqlguard.attacks import ATTACKS, CONFIGURATIONS, ablation, read_truth, render_ablation, run_attack
from sqlguard.sandbox import Layers

NATIVELY_BLOCKED = {"stacked_drop", "stacked_update"}  # Python's sqlite3 refuses two statements in one call, whatever we do
SLOW = {"infinite_cte", "triple_cross_join", "cross_join_constant", "cross_join_one_sided", "cross_join_arithmetic"}  # each runs for seconds when unprotected
RESOURCE = SLOW | {"join_explosion", "row_dump"}
FAST = [a for a in ATTACKS if a.name not in SLOW]  # the slow ones are covered separately below


@pytest.fixture(scope="module")
def results(db, policy):
    fast_configs = {k: v for k, v in CONFIGURATIONS.items()}
    return ablation(db, policy, FAST, fast_configs)


def succeeded(results, config):
    return {name for name, ok in results[config].items() if ok}


def test_attack_names_are_unique_and_every_attack_has_a_known_goal():
    assert len({a.name for a in ATTACKS}) == len(ATTACKS) == 52
    assert {a.goal for a in ATTACKS} == {"write", "leak_salary", "leak_email", "leak_secret", "schema_probe", "dos", "oracle", "aggregate_leak"}


def test_with_no_layers_almost_every_attack_is_real(results):
    working = succeeded(results, "none")
    assert NATIVELY_BLOCKED.isdisjoint(working)  # an honest suite reports the attacks that were never a threat
    assert {a.name for a in FAST} - NATIVELY_BLOCKED == working


def test_with_every_layer_on_nothing_gets_through(results):
    assert succeeded(results, "all") == set()


def test_the_three_engine_enforced_layers_alone_stop_everything_in_this_suite(results):
    assert succeeded(results, "readonly+authorizer+limits") == set()


def test_each_layer_alone_leaves_gaps(results):
    assert succeeded(results, "parser") == {"join_explosion", "row_dump"}  # the parser never limits what a legal query costs
    assert succeeded(results, "authorizer") == {"join_explosion", "row_dump"}  # the authorizer does not cap rows
    assert succeeded(results, "readonly") >= {"direct_salary", "hidden_keys"}  # read-only mode stops writes, not reads
    assert RESOURCE.isdisjoint(succeeded(results, "limits")) and "direct_salary" in succeeded(results, "limits")


def test_readonly_stops_every_write_except_possibly_attach(results):
    # On SQLite 3.49 a read-only connection can still ATTACH and create a new file; other versions may differ.
    writes = {a.name for a in FAST if a.goal == "write"} - NATIVELY_BLOCKED
    assert writes & succeeded(results, "readonly") <= {"attach_new_db"}


def test_the_slow_resource_attacks_are_real_when_unprotected_and_stopped_by_the_time_limit(db, policy):
    truth = read_truth(db)
    for name in ("infinite_cte", "triple_cross_join", "cross_join_arithmetic"):
        attack = next(a for a in ATTACKS if a.name == name)
        assert run_attack(attack, db, policy, Layers.none(), truth)[0], name
        assert not run_attack(attack, db, policy, Layers(), truth)[0], name


def test_the_parser_stops_the_obvious_cross_joins_but_the_arithmetic_one_needs_the_time_limit(db, policy):
    truth = read_truth(db)
    parser_only = Layers(parser=True, readonly=False, authorizer=False, limits=False)
    outcomes = {n: run_attack(next(a for a in ATTACKS if a.name == n), db, policy, parser_only, truth) for n in ("cross_join_constant", "cross_join_one_sided", "cross_join_arithmetic")}
    assert not outcomes["cross_join_constant"][0] and outcomes["cross_join_constant"][1].code == "cartesian_product"
    assert not outcomes["cross_join_one_sided"][0] and outcomes["cross_join_one_sided"][1].code == "cartesian_product"
    assert outcomes["cross_join_arithmetic"][0]  # parsing alone cannot separate this from a legitimate join
    time_limit_only = Layers(parser=False, readonly=False, authorizer=False, limits=True)
    assert not run_attack(next(a for a in ATTACKS if a.name == "cross_join_arithmetic"), db, policy, time_limit_only, truth)[0]


def test_the_report_has_one_row_per_category_and_a_total(results):
    text = render_ablation(results, FAST)
    for category in ("write", "stacked", "personal data", "obfuscation", "hidden table", "statistics", "resource", "inference", "All"):
        assert f"| {category}" in text or f"| **{category}**" in text
