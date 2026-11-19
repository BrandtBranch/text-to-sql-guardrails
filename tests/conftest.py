import pytest

from sqlguard.db import build_database
from sqlguard.guard import Policy


@pytest.fixture(scope="session")
def db(tmp_path_factory):
    return build_database(tmp_path_factory.mktemp("db") / "consulting.db")


@pytest.fixture(scope="session")
def policy(db):
    return Policy.for_database(db)
