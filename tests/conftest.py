import pytest

from wakeboard.config import Settings
from wakeboard.db import connect


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path)


@pytest.fixture
def conn(settings):
    c = connect(settings.data_dir / "wakeboard.db")
    yield c
    c.close()
