"""
Pytest conftest for Chambers UAS integration tests.

Provides fixtures for docker compose lifecycle and GCS client access.
"""

import shutil
import subprocess
import time

import pytest

# Skip all tests in this directory if docker is not available
docker_available = shutil.which("docker") is not None


def pytest_collection_modifyitems(items):
    """Skip all tests if docker is not running."""
    if not docker_available:
        skip_marker = pytest.mark.skip(reason="Docker is not available")
        for item in items:
            item.add_marker(skip_marker)
        return

    # Also check if the docker daemon is actually running
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            skip_marker = pytest.mark.skip(reason="Docker daemon is not running")
            for item in items:
                item.add_marker(skip_marker)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        skip_marker = pytest.mark.skip(reason="Docker daemon is not reachable")
        for item in items:
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def docker_compose_up():
    """Start docker compose services for the test session, tear down after."""
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d"],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        pytest.fail(f"docker compose up failed: {e.stderr.decode()}")

    # Give services a moment to become healthy
    time.sleep(5)

    yield

    subprocess.run(
        ["docker", "compose", "down"],
        capture_output=True,
        timeout=60,
    )


@pytest.fixture(scope="session")
def gcs_url():
    """Return the base URL for the GCS HTTP API."""
    return "http://localhost:8080"


@pytest.fixture
async def gcs_client(gcs_url):
    """Async HTTP client pointed at the GCS API."""
    import httpx

    async with httpx.AsyncClient(base_url=gcs_url, timeout=10.0) as client:
        yield client
