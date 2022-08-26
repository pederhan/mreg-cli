import sys

if sys.version_info > (3, 6):
    from contextlib import nullcontext
from typing import Any, Dict

import pytest
from mreg_cli import host
from mreg_cli.exceptions import CliWarning
from pytest_httpserver import HTTPServer


def _setup_zoneinfo_for_hostname(
    httpserver: HTTPServer,
    hostname: str,
    sample_zone: Dict[str, Any],
    status: int = 200,
) -> None:
    httpserver.expect_oneshot_request(
        f"/api/v1/zones/forward/hostname/{hostname}",
    ).respond_with_json(sample_zone, status=status)


@pytest.mark.parametrize(
    "hostname,expect",
    [("localhost", False), ("foo", False), ("foo.example.com", True)],
)
def test_zoneinfo_for_hostname(
    httpserver: HTTPServer,
    sample_zone: Dict[str, Any],
    hostname: str,
    expect: bool,  # expect a result or not
) -> None:
    _setup_zoneinfo_for_hostname(httpserver, hostname, sample_zone)
    resp = host.zoneinfo_for_hostname(hostname)
    if expect:
        assert resp == sample_zone
    else:
        assert resp is None


@pytest.mark.skipif(
    sys.version_info < (3, 7),
    reason="requires python3.7 or higher (contextlib.nullcontext",
)
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("require_zone", [True, False])
@pytest.mark.parametrize("is404", [True, False])
@pytest.mark.parametrize("delegation", [True, False])
def test_check_zone_for_hostname(
    httpserver: HTTPServer,
    sample_zone: Dict[str, Any],
    force: bool,
    require_zone: bool,
    is404: bool,  #
    delegation: bool,  # Include delegation in the result
) -> None:
    hostname = "foo.example.com"
    if is404:
        status = 404
        sample_zone = {}
    else:
        status = 200

    if delegation and sample_zone:
        sample_zone["delegation"] = {
            "name": "foo.example.com"
        }  # FIXME: use a more accurate delegation value

    _setup_zoneinfo_for_hostname(httpserver, hostname, sample_zone, status=status)

    ctx = nullcontext()
    if not sample_zone:
        if require_zone or not force:
            ctx = pytest.raises(CliWarning)
    elif delegation and not force:
        ctx = pytest.raises(CliWarning)

    # Call function within context manager
    with ctx as exc_info:
        host.check_zone_for_hostname(hostname, force, require_zone)

    if exc_info is not None:
        assert isinstance(exc_info.value, CliWarning)
        assert "zone" in exc_info.exconly().lower()  # TODO: improve this check?


@pytest.mark.skip("Show mercy...")
def test__get_ip_from_args() -> None:
    pass