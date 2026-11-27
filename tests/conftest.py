import pytest

from gatekeep.guard.policy import Policy
from gatekeep.scenarios.loader import load_scenarios


@pytest.fixture(scope="session")
def scenarios():
    return {s.id: s for s in load_scenarios()}


@pytest.fixture(scope="session")
def policy():
    return Policy.load()
