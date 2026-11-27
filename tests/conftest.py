import pytest

from gatekeep.guard.policy import Policy
from gatekeep.scenarios.loader import load_scenarios


@pytest.fixture(scope="session")
def scenarios():
    return {s.id: s for s in load_scenarios()}


@pytest.fixture(scope="session")
def policy():
    return Policy.load()


@pytest.fixture(scope="session")
def ctx():
    return {"alert_id": "A-1", "attacker_value": "203.0.113.66", "decoy_host": "fin-db-01",
            "exfil_url": "https://collect.attacker.invalid/ingest"}
