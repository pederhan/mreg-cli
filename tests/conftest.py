from typing import Any, Dict, Iterator
from mreg_cli import util
import pytest
from pytest_httpserver import HTTPServer


@pytest.fixture
def httpserver_original(httpserver: HTTPServer) -> Iterator[HTTPServer]:
    # A copy of the original httpserver, since we shadow the original
    # with our own version.
    yield httpserver


@pytest.fixture
def httpserver(httpserver: HTTPServer) -> Iterator[HTTPServer]:
    """Shadows the pytest_httpserver.httpserver fixture with our own that
    assigns the result of httpserver.url_for('') to util.mregurl."""
    util.mregurl = httpserver.url_for("")
    yield httpserver  # yield so that the httpserver is closed after the test


@pytest.fixture
def sample_network() -> Dict[str, Any]:
    return {
        "id": 66,
        "excluded_ranges": [
            {
                "id": 21,
                "created_at": "2020-12-03T17:04:23.876818+01:00",
                "updated_at": "2020-12-03T17:04:23.876855+01:00",
                "start_ip": "10.0.1.20",
                "end_ip": "10.0.1.30",
                "network": 66,
            }
        ],
        "created_at": "2020-12-03T17:04:23.200211+01:00",
        "updated_at": "2020-12-03T17:04:23.361019+01:00",
        "network": "10.0.1.0/24",
        "description": "Frozzzen",
        "vlan": None,
        "dns_delegated": False,
        "category": "",
        "location": "",
        "frozen": True,
        "reserved": 3,
    }
