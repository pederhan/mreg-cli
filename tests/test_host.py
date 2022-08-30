from argparse import Namespace
import sys
import urllib.parse

from typing import Any, Callable, ContextManager, Dict, List, Optional, Type

import pytest
from mreg_cli import host, util
from mreg_cli.exceptions import CliWarning, HostNotFoundWarning
from pytest_httpserver import HTTPServer
from .handlers import (
    assoc_mac_to_ip_handler,
    cname_exists_handler,
    _get_ip_from_args_handler,
    zoneinfo_for_hostname_handler,
    _host_info_by_name_handler,
)
from .utils import requires_nullcontext, macaddresses
from .compat import nullcontext


def mock__get_ip_from_args(
    sample_ipaddress: Dict[str, Any]
) -> Any:  # terrible annotation
    def func(ip: str, force: bool, ipversion: Optional[int] = None) -> Dict[str, Any]:
        return sample_ipaddress["ipaddress"]

    return func


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


@pytest.mark.parametrize(
    "ip,ipversion,is_network,exception",
    [
        ("10.0.1.4", 4, False, None),
        ("10.0.1.0/24", 4, True, None),
        ("10.0.1.4", 6, False, CliWarning),
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", 6, False, None),
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", 4, False, CliWarning),
    ],
)
@pytest.mark.parametrize("ip_in_use", [True, False])
@pytest.mark.parametrize("ip_reserved", [True, False])
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("network_frozen", [True, False])
def test__get_ip_from_args(
    httpserver: HTTPServer,
    sample_network: Dict[str, Any],
    sample_network_ipv6: Dict[str, Any],
    sample_host: Dict[str, Any],
    ip: str,
    ipversion: int,
    is_network: bool,
    exception: Optional[Type[Exception]],
    force: bool,
    ip_in_use: bool,
    ip_reserved: bool,
    network_frozen: bool,
) -> None:
    """NOTE: this is an extremely complicated function to test,
    as it has numerous branches and failure modes.

    We attempt to test each good path extensively, but not every possible failure path.
    If bug reports for the failure paths are received, we can add them to the test.
    """
    if ipversion == 4:
        net = sample_network
    else:
        net = sample_network_ipv6

    _get_ip_from_args_handler(
        httpserver,
        sample_network=net,
        sample_host=sample_host,
        ip=ip,
        is_network=is_network,
        ip_in_use=ip_in_use,
        ip_reserved=ip_reserved,
        network_frozen=network_frozen,
    )
    ctx = nullcontext()
    if exception is not None:
        ctx = pytest.raises(exception)
    elif network_frozen and not force:
        ctx = pytest.raises(CliWarning)
    elif (ip_in_use and not force) and not is_network:
        ctx = pytest.raises(CliWarning)
    with ctx:
        res = host._get_ip_from_args(ip, force, ipversion)


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

    monkeypatch.setattr(
        host, "_get_ip_from_args", mock__get_ip_from_args(sample_ipaddress)
    )

    # Create host handler
    httpserver.expect_oneshot_request(
        "/api/v1/hosts/", method="POST"
    ).respond_with_data(status=201)

    # FIXME: WHY IS THIS DUPLICATED???
    # FIXME
    # FIXME

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


@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("cnames", [[], ["foo-c.example.com"]])
@pytest.mark.parametrize("has_srv", [True, False])
@pytest.mark.parametrize("has_natpr", [True, False])
def test_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_srv: Dict[str, Any],
    sample_naptr: Dict[str, Any],
    force: bool,
    cnames: List[str],
    has_srv: bool,
    has_natpr: bool,
) -> None:
    """Remove a host from the zone."""
    args = Namespace(name=sample_host["name"], force=force)

    sample_host["cnames"] = cnames
    _host_info_by_name_handler(httpserver, sample_host)

    # DELETE handler
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{sample_host['name']}", method="DELETE"
    ).respond_with_data(status=204)

    # NAPTR records handler (no query matching)
    naptr_results = [sample_naptr] if has_natpr else []
    httpserver.expect_oneshot_request(
        f"/api/v1/naptrs/", method="GET"
    ).respond_with_json({"results": naptr_results, "next": None})

    # SRV records handler (no query matching)
    srv_results = [sample_srv] if has_srv else []
    httpserver.expect_oneshot_request(f"/api/v1/srvs/", method="GET").respond_with_json(
        {"results": srv_results, "next": None}
    )

    if (cnames or has_srv or has_natpr) and not force:
        with pytest.raises(CliWarning):
            host.remove(args)
    else:
        host.remove(args)


@pytest.mark.parametrize("name", ["foo.example.com", None])
@pytest.mark.parametrize("comment", ["this is an example comment", None])
@pytest.mark.parametrize("contact", ["user@example.com", None])
def test_find(
    httpserver: HTTPServer,
    name: Optional[str],
    comment: Optional[str],
    contact: Optional[str],
    sample_host: Dict[str, Any],
) -> None:
    """Find a host by name."""
    args = Namespace(name=name, comment=comment, contact=contact)

    # Re-usable handler for both GET requests from find()
    httpserver.expect_request("/api/v1/hosts/", method="GET").respond_with_json(
        {"count": 1, "results": [sample_host], "next": None}
    )

    if all(arg is None for arg in (name, comment, contact)):
        with pytest.raises(CliWarning):
            host.find(args)
    else:
        host.find(args)


@pytest.mark.parametrize("old_name", ["foo.example.com"])
@pytest.mark.parametrize("new_name", ["bar.example.com"])
@pytest.mark.parametrize("force", [True, False])
def test_rename(
    httpserver: HTTPServer,
    monkeypatch: pytest.MonkeyPatch,
    sample_zone: Dict[str, Any],
    old_name: str,
    new_name: str,
    force: bool,
) -> None:
    # TODO: Add force=True tests

    args = Namespace(old_name=old_name, new_name=new_name, force=force)

    # TODO: replace monkeypatch with better mocking
    def mock_resolve_input_name(name: str) -> str:
        if name == new_name:
            raise HostNotFoundWarning
        return name

    # Handlers for lookups
    monkeypatch.setattr(host, "resolve_input_name", mock_resolve_input_name)
    cname_exists_handler(httpserver, [], None)
    zoneinfo_for_hostname_handler(httpserver, new_name, sample_zone, status=200)

    # Handler for PATCH request
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{old_name}", method="PATCH"
    ).respond_with_data(status=200)

    host.rename(args)


# TODO: expand on parameters for this test
@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("comment", ["this is an example comment"])
def test_set_comment(
    httpserver: HTTPServer, sample_host: Dict[str, Any], name: str, comment: str
) -> None:
    _host_info_by_name_handler(httpserver, sample_host)

    httpserver.expect_oneshot_request(
        "/api/v1/hosts/foo.example.com",
        method="PATCH",
        data=f"comment={urllib.parse.quote_plus(comment)}",
    ).respond_with_data(status=200)

    args = Namespace(name=name, comment=comment)
    host.set_comment(args)


# TODO: expand on parameters for this test
#       As of now, we just test with a valid email address
@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("contact", ["user@example.com"])
def test_set_contact(
    httpserver: HTTPServer, sample_host: Dict[str, Any], name: str, contact: str
) -> None:
    _host_info_by_name_handler(httpserver, sample_host)

    httpserver.expect_oneshot_request(
        "/api/v1/hosts/foo.example.com",
        method="PATCH",
        data=f"contact={urllib.parse.quote_plus(contact)}",
    ).respond_with_data(status=200)

    args = Namespace(name=name, contact=contact)
    host.set_contact(args)


def _ip_add_handler(
    httpserver: HTTPServer,
    monkeypatch: pytest.MonkeyPatch,
    sample_ipaddress: Dict[str, Any],
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    macaddress: Optional[str],
    force: bool,
    host_exists: bool,
    host_has_ip: bool,
    duplicate_ip: bool,
) -> None:

    # FIXME: _ip_add() will never succeed if the host doesn't exist.
    #        This is a bug caused by util.host_info_by_name() raising
    #        CliWarning when `follow_cname=True` is passed to it (which is the default)
    #        and the host doesn't exist.
    #
    #        Passing `host_exist=False` will cause the test to fail

    # sample_ipaddress["ipaddress"] = ip
    if not host_has_ip:
        sample_host["ipaddresses"] = []
    elif duplicate_ip:
        sample_host["ipaddresses"] = [sample_ipaddress]

    monkeypatch.setattr(
        host, "_get_ip_from_args", mock__get_ip_from_args(sample_ipaddress)
    )
    # resolve_input_name_handler(httpserver, sample_host, name)
    _host_info_by_name_handler(
        httpserver,
        sample_host if host_exists else None,  # type: ignore
        cname=True,
        hostname=name,
    )
    if not host_exists:
        httpserver.expect_oneshot_request(
            f"/api/v1/hosts/",
            method="POST",
            # data=f"name={urllib.parse.quote_plus(name)}&ipaddress={urllib.parse.quote_plus(ipaddress)}",
        ).respond_with_data(status=201)
    if macaddress is not None:
        httpserver.expect_oneshot_request(
            f"/api/v1/hosts/{name}", method="GET"
        ).respond_with_json({"ipaddresses": sample_host["ipaddresses"]})
        assoc_mac_to_ip_handler(httpserver, macaddress, sample_ipaddress)
    # else:
    # TODO: add body matching
    httpserver.expect_oneshot_request(
        "/api/v1/ipaddresses/", method="POST"
    ).respond_with_data(status=201)


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("ip", ["10.0.1.5", "10.0.1.0/24"])  # IP and CIDR
@pytest.mark.parametrize(
    "macaddress", macaddresses(limit=1, with_none=True)
)  # MAC address and None
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("host_exists", [True])  # Not a CLI arg  # FIXME: add False
@pytest.mark.parametrize("host_has_ip", [True, False])  # Not a CLI arg
@pytest.mark.parametrize("duplicate_ip", [True, False])  # Not a CLI arg
def test_a_add(
    httpserver: HTTPServer,
    monkeypatch: pytest.MonkeyPatch,
    sample_ipaddress: Dict[str, Any],
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    macaddress: Optional[str],
    force: bool,
    host_exists: bool,
    host_has_ip: bool,
    duplicate_ip: bool,
) -> None:
    _ip_add_handler(
        httpserver,
        monkeypatch,
        sample_ipaddress,
        sample_host,
        name,
        ip,
        macaddress,
        force,
        host_exists,
        host_has_ip,
        duplicate_ip,
    )
    args = Namespace(name=name, ip=ip, macaddress=macaddress, force=force)

    # TODO: refactor to reduce code duplication between this and test_aaaa_add()
    ctx = nullcontext()  # type: ContextManager[Optional[Any]]
    msg = ""
    if host_has_ip and not force:
        ctx = pytest.raises(CliWarning)
    elif (
        sample_host["ipaddresses"] and ip == sample_host["ipaddresses"][0]["ipaddress"]
    ):
        ctx = pytest.raises(CliWarning)
    with ctx as exc_info:
        host.a_add(args)


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize(
    "ip",
    [
        "7593:4588:f58f:f153:167b:86da:1de3:da80",
        "7593:4588:f58f:f153:0000:0000:0000:0000/64",
    ],
)  # IP and CIDR
@pytest.mark.parametrize(
    "macaddress", macaddresses(limit=1, with_none=True)
)  # MAC address and None
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("host_exists", [True])  # Not a CLI arg
@pytest.mark.parametrize("host_has_ip", [True, False])  # Not a CLI arg
@pytest.mark.parametrize("duplicate_ip", [True, False])  # Not a CLI arg
def test_aaaa_add(
    httpserver: HTTPServer,
    monkeypatch: pytest.MonkeyPatch,
    sample_ipaddress: Dict[str, Any],
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    macaddress: Optional[str],
    force: bool,
    host_exists: bool,
    host_has_ip: bool,
    duplicate_ip: bool,
) -> None:
    _ip_add_handler(
        httpserver,
        monkeypatch,
        sample_ipaddress,
        sample_host,
        name,
        ip,
        macaddress,
        force,
        host_exists,
        host_has_ip,
        duplicate_ip,
    )
    args = Namespace(name=name, ip=ip, macaddress=macaddress, force=force)

    ctx = nullcontext()  # type: ContextManager[Optional[Any]]
    msg = ""
    if host_has_ip and not force:
        ctx = pytest.raises(CliWarning)
    elif (
        sample_host["ipaddresses"] and ip == sample_host["ipaddresses"][0]["ipaddress"]
    ):
        ctx = pytest.raises(CliWarning)
    with ctx as exc_info:
        host.aaaa_add(args)
