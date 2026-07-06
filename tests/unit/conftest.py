"""Shared fixtures/helpers for unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def fixture(*parts: str) -> Path:
    return FIXTURES.joinpath(*parts)
