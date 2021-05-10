from ops.testing import Harness
from charm import NrpeCharm
import pytest


@pytest.fixture
def harness():
    _harness = Harness(NrpeCharm)
    _harness.begin()
    yield _harness
