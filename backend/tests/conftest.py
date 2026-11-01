"""Test fixtures and setup for Vulnex AI."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.config import settings
from app.storage.database import init_db
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    # Use temporary database for tests
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db_path = temp_db.name
    temp_db.close()

    settings.database_path = temp_db_path
    init_db(temp_db_path)

    yield

    # Cleanup test db
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
