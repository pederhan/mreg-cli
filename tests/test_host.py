from argparse import Namespace
import sys

if sys.version_info >= (3, 7):
    from contextlib import nullcontext
from typing import Any, Dict, Optional, Type

import pytest
from mreg_cli import host, util
from mreg_cli.exceptions import CliWarning, HostNotFoundWarning
from pytest_httpserver import HTTPServer
from .handlers import (
    assoc_mac_to_ip_handler,
    cname_exists_handler,
    zoneinfo_for_hostname_handler,
)


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
    zoneinfo_for_hostname_handler(httpserver, hostname, sample_zone)
    resp = host.zoneinfo_for_hostname(hostname)
    if expect:
        assert resp == sample_zone
    else:
        assert resp is None


@pytest.mark.skipif(
    sys.version_info < (3, 7),
    reason="requires python3.7 or higher (contextlib.nullcontext",
)  # can also use pytest.importorskip("contextlib")
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

    zoneinfo_for_hostname_handler(httpserver, hostname, sample_zone, status=status)

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


@pytest.mark.parametrize(
    "ip,ipversion,exception",
    [
        # IPv4 address input
        ("192.168.1.1", 4, None),
        ("192.168.1.1", 6, CliWarning),
        ("192.168.1.1", 5, CliWarning),  # Invalid version
        ("192.168.1.1", None, CliWarning),  # No version
        # IPv6 Address input
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", 6, None),
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", 4, CliWarning),
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", 5, CliWarning),  # Invalid version
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", None, CliWarning),  # No version
        # Other input (invalid)
        ("foo", 4, CliWarning),
        ("foo", 6, CliWarning),
        ("foo", 5, CliWarning),
        ("foo", None, CliWarning),  # No version
    ],
)
def test__check_ipversion(
    ip: str, ipversion: int, exception: Optional[Type[Exception]]
) -> None:
    if exception is not None:
        with pytest.raises(exception):
            host._check_ipversion(ip, ipversion)
    else:
        host._check_ipversion(ip, ipversion)


@pytest.mark.parametrize(
    "name", ["foo.example.com"]
)  # NOTE: testing without FQDN requires patching util.config
@pytest.mark.parametrize(
    "ip", ["10.0.1.2", "7593:4588:f58f:f153:167b:86da:1de3:da80", None]
)
@pytest.mark.parametrize("contact", ["user@example.com", None])
@pytest.mark.parametrize("comment", ["this is a comment", None])
@pytest.mark.parametrize(
    "macaddress", ["28-85-B1-60-54-DC", None]
)  # NOTE: use macaddresses(with_none=True)?
@pytest.mark.parametrize("force", [True, False])
def test_add(
    httpserver: HTTPServer,
    sample_zone: Dict[str, Any],
    sample_ipaddress: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    ip: str,
    contact: Optional[str],
    comment: Optional[str],
    macaddress: Optional[str],
    force: bool,
) -> None:
    """NOTE: host.add() is quite involved, so we're not testing every possible
    failure case.

    TODO: verify that this holds true
    """

    # TODO: add strategy for generating various args.name values
    #       similar to test_clean_hostname()
    args = Namespace(
        name=name,
        ip=ip,
        contact=contact,
        comment=comment,
        macaddress=macaddress,
        force=force,
    )

    # TODO: replace monkeypatch with better mocking
    def mock_resolve_input_name(name: str) -> str:
        raise HostNotFoundWarning

    monkeypatch.setattr(host, "resolve_input_name", mock_resolve_input_name)

    zoneinfo_for_hostname_handler(
        httpserver, "foo.example.com", sample_zone, status=200
    )

    # Mock that the name doesn't exist
    # TODO: add query string matching for this
    cname_exists_handler(httpserver, [], None)

    # TODO: replace monkeypatch with better mocking
    # Mocking this until we have a proper test for _get_ip_from_args()
    def mock__get_ip_from_args(
        ip: str, force: bool, ipversion: Optional[int] = None
    ) -> Dict[str, Any]:
        return sample_ipaddress["ipaddress"]

    monkeypatch.setattr(host, "_get_ip_from_args", mock__get_ip_from_args)

    # Create host handler
    httpserver.expect_oneshot_request(
        "/api/v1/hosts/", method="POST"
    ).respond_with_data(status=201)

    # Create host creation handler
    httpserver.expect_oneshot_request(
        "/api/v1/hosts/", method="POST"
    ).respond_with_data(status=201)

    # Associate MAC address handler
    if macaddress is not None:
        # IP data for host handler
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/foo.example.com",
            method="GET",
            # Pretend that the host exists
        ).respond_with_json({"ipaddresses": [sample_ipaddress]})

        # Assoc MAC address handler
        assoc_mac_to_ip_handler(httpserver, macaddress, sample_ipaddress)

    # Expect to fail if a host already has the MAC
    # and force is not enabled
    if not force and macaddress:
        with pytest.raises(CliWarning):
            host.add(args)
    else:
        host.add(args)