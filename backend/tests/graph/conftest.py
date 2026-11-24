import copy
from collections.abc import Callable

import pytest
from graph_helpers import load_payload


@pytest.fixture
def fixture_payload() -> Callable[[str], dict]:
    """Fresh deep copy of a fixture so tests can mutate it."""
    return lambda name: copy.deepcopy(load_payload(name))
