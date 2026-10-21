import pytest


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("CROSSKILL_OFFLINE", "1")
