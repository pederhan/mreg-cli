from argparse import Namespace
from site import venv
import sys
import urllib.parse

from typing import Any, Callable, ContextManager, Dict, List, Optional, Type

import pytest
from mreg_cli import host, util
from mreg_cli.exceptions import CliError, CliWarning, HostNotFoundWarning
from pytest_httpserver import HTTPServer
from .handlers import (
    _ip_change_handler,
    _ip_move_handler,
    assoc_mac_to_ip_handler,
    cname_exists_handler,
    _get_ip_from_args_handler,
    zoneinfo_for_hostname_handler,
    _host_info_by_name_handler,
    _ip_add_handler,
)
from .utils import (
    patch__get_ip_from_args,
    requires_nullcontext,
    macaddresses,
)
from .compat import nullcontext





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

    # TODO: replace monkeypatch with better mocking
    # Mocking this until we have a proper test for _get_ip_from_args()
    patch__get_ip_from_args(monkeypatch, sample_ipaddress)
    monkeypatch.setattr(host, "resolve_input_name", mock_resolve_input_name)

    zoneinfo_for_hostname_handler(
        httpserver, "foo.example.com", sample_zone, status=200
    )

    # Mock that the name doesn't exist
    # TODO: add query string matching for this
    cname_exists_handler(httpserver, [], None)

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
@pytest.mark.parametrize("has_ptr_override", [True, False])
def test_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_srv: Dict[str, Any],
    sample_naptr: Dict[str, Any],
    force: bool,
    cnames: List[str],
    has_srv: bool,
    has_natpr: bool,
    has_ptr_override: bool,
) -> None:
    """Remove a host from the zone."""
    args = Namespace(name=sample_host["name"], force=force)

    sample_host["cnames"] = cnames
    if not has_ptr_override:
        sample_host["ptr_overrides"] = []
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

    # TODO: add warning message tests
    if (cnames or has_srv or has_natpr or has_ptr_override) and not force:
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


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("ip", ["10.0.0.5", "10.0.1.0/24"])  # IP and CIDR
@pytest.mark.parametrize(
    "macaddress", macaddresses(limit=1, with_none=True)
)  # MAC address and None
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize(
    "host_exists", [True, False]
)  # Not a CLI arg  # FIXME: add False
@pytest.mark.parametrize("host_has_ip", [True, False])  # Not a CLI arg
@pytest.mark.parametrize("host_has_mac", [True, False])  # Not a CLI arg
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
    host_has_mac: bool,
    duplicate_ip: bool,
) -> None:
    do_test_ip_add(
        httpserver,
        monkeypatch,
        sample_ipaddress,
        sample_host,
        name,
        ip,
        macaddress=macaddress,
        force=force,
        host_exists=host_exists,
        host_has_ip=host_has_ip,
        host_has_mac=host_has_mac,
        duplicate_ip=duplicate_ip,
        ipversion=4,
    )


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
@pytest.mark.parametrize("host_has_mac", [False])  # Not a CLI arg
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
    host_has_mac: bool,
    duplicate_ip: bool,
) -> None:
    do_test_ip_add(
        httpserver,
        monkeypatch,
        sample_ipaddress,
        sample_host,
        name,
        ip,
        macaddress=macaddress,
        force=force,
        host_exists=host_exists,
        host_has_ip=host_has_ip,
        host_has_mac=host_has_mac,
        duplicate_ip=duplicate_ip,
        ipversion=6,
    )


def do_test_ip_add(
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
    host_has_mac: bool,
    duplicate_ip: bool,
    ipversion: int,  # what decides which function is tested
) -> None:
    """Tests either host.a_add() or host.aaaa_add() depending on `ipversion`."""
    # NOTE: this is a very complex and long test function due to the
    # many different combinations of parameters that need to be tested, and their
    # different behaviors.

    _ip_add_handler(
        httpserver,
        monkeypatch,
        sample_ipaddress,
        sample_host,
        name,
        ip,
        macaddress=macaddress,
        force=force,
        host_exists=host_exists,
        host_has_ip=host_has_ip,
        host_has_mac=host_has_mac,
        duplicate_ip=duplicate_ip,
    )
    args = Namespace(name=name, ip=ip, macaddress=macaddress, force=force)

    ctx = nullcontext()  # type: ContextManager[Optional[Any]]
    msg = ""

    # _ip_add has 2 fundamentally different branches: host exists/doesn't exist
    if host_exists:
        # top level `if not force`?
        if host_has_ip and not force:
            ctx = pytest.raises(CliWarning)
            msg = "A/AAAA record"
        elif host_has_ip and ip == sample_host["ipaddresses"][0]["ipaddress"]:
            ctx = pytest.raises(CliWarning)
            msg = "already has IP"
    else:
        if macaddress is not None and host_has_mac and not force:
            ctx = pytest.raises(CliWarning)
            msg = "has existing mac"

    if ipversion == 4:
        func = host.a_add
    elif ipversion == 6:
        func = host.aaaa_add
    else:
        raise ValueError(f"invalid ipversion: {ipversion}")

    with ctx as exc_info:
        func(args)

    if exc_info is not None:
        assert msg.lower() in exc_info.exconly().lower()

@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("old", ["10.0.1.4"])
@pytest.mark.parametrize("new", ["10.0.1.4", "10.0.1.5"])
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("owns_old_ip", [True, False])  # Not a CLI arg
def test_a_change(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_network: Dict[str, Any],
    name: str,
    old: str,
    new: str,
    force: bool,
    owns_old_ip: bool,
) -> None:
    args = Namespace(name=name, old=old, new=new, force=force)

    _ip_change_handler(
        httpserver,
        sample_host,
        sample_network,
        old,
        new,
        force,
        owns_old_ip,
        ipversion=4,
    )

    ctx = nullcontext()
    msg = ""

    if old == new:
        ctx = pytest.raises(CliWarning)
        msg = "equal"
    elif not owns_old_ip:
        ctx = pytest.raises(CliWarning)
        msg = "not owned"
    with ctx as exc_info:
        host.a_change(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("old", ["7593:4588:f58f:f153:DEAD:BEEF:1234:1234"])
@pytest.mark.parametrize(
    "new",
    [
        "7593:4588:f58f:f153:DEAD:BEEF:1234:1234",
        "7593:4588:f58f:f153:BEEF:BEEF:1234:1234",
    ],
)
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("owns_old_ip", [True, False])  # Not a CLI arg
def test_aaaa_change(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_network_ipv6: Dict[str, Any],
    name: str,
    old: str,
    new: str,
    force: bool,
    owns_old_ip: bool,
) -> None:
    """Just like test_a_change, but for AAAA records."""

    # TODO: refactor this to reduce duplication with test_a_change

    args = Namespace(name=name, old=old, new=new, force=force)

    _ip_change_handler(
        httpserver,
        sample_host,
        sample_network_ipv6,
        old,
        new,
        force,
        owns_old_ip,
        ipversion=4,
    )

    ctx = nullcontext()
    msg = ""

    if old == new:
        ctx = pytest.raises(CliWarning)
        msg = "equal"
    elif not owns_old_ip:
        ctx = pytest.raises(CliWarning)
        msg = "not owned"
    with ctx as exc_info:
        host.aaaa_change(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("ip", ["10.0.1.4"])
@pytest.mark.parametrize("from_host", ["foo.example.com"])
@pytest.mark.parametrize("to_host", ["bar.example.com"])
@pytest.mark.parametrize("use_ptr", [True, False])
@pytest.mark.parametrize("host_has_ip", [True, False])  # Not a CLI arg
def test_a_move(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    ip: str,
    from_host: str,
    to_host: str,
    use_ptr: bool,
    host_has_ip: bool,
) -> None:
    args = Namespace(ip=ip, fromhost=from_host, tohost=to_host)

    _ip_move_handler(
        httpserver, sample_host, ip, from_host, to_host, use_ptr, host_has_ip
    )
    ctx = nullcontext()
    msg = ""

    if not host_has_ip and not use_ptr:
        ctx = pytest.raises(CliWarning)
        msg = "no ip"
    with ctx as exc_info:
        host.a_move(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("ip", ["7593:4588:f58f:f153:DEAD:BEEF:1234:1234"])
@pytest.mark.parametrize("from_host", ["foo.example.com"])
@pytest.mark.parametrize("to_host", ["bar.example.com"])
@pytest.mark.parametrize("use_ptr", [True, False])
@pytest.mark.parametrize("host_has_ip", [True, False])  # Not a CLI arg
def test_aaaa_move(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    ip: str,
    from_host: str,
    to_host: str,
    use_ptr: bool,
    host_has_ip: bool,
) -> None:
    args = Namespace(ip=ip, fromhost=from_host, tohost=to_host)

    _ip_move_handler(
        httpserver, sample_host, ip, from_host, to_host, use_ptr, host_has_ip
    )
    ctx = nullcontext()
    msg = ""

    if not host_has_ip and not use_ptr:
        ctx = pytest.raises(CliWarning)
        msg = "no ip"
    with ctx as exc_info:
        host.aaaa_move(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("ip", ["10.0.0.5"])
@pytest.mark.parametrize("owns_ip", [True, False])  # Not a CLI arg # HOST_owns_ip?
def test_a_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    owns_ip: bool,
) -> None:
    do_test_ip_remove(httpserver, sample_host, name, ip, owns_ip, ipversion=4)


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("ip", ["7593:4588:f58f:f153:dead:beef:1234:1234"])
@pytest.mark.parametrize("owns_ip", [True, False])  # Not a CLI arg # HOST_owns_ip?
def test_aaaa_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    owns_ip: bool,
) -> None:
    # NOTE: host._ip_remove checks rec["ipaddress"] == args.ip.lower()
    # which will fail if the record returned by the API has uppercase IPv6
    # Maybe we should fix that?
    do_test_ip_remove(httpserver, sample_host, name, ip, owns_ip, ipversion=6)


def do_test_ip_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    ip: str,
    owns_ip: bool,
    ipversion: int,
) -> None:
    """Tests host.a_remove() and host.aaaa_remove()."""
    args = Namespace(name=name, ip=ip)

    if owns_ip:
        sample_host["ipaddresses"][0]["ipaddress"] = ip
    else:
        # To simulate this, we remove the IP from the host
        # this should be the same as if the host doesn't own the IP
        #
        # TODO: add another IP to the host to verify this claim
        sample_host["ipaddresses"] = []  # host owns no IPs

    _host_info_by_name_handler(httpserver, sample_host)

    msg = ""
    if owns_ip:
        ip_id = sample_host["ipaddresses"][0]["id"]
        httpserver.expect_oneshot_request(
            f"/api/v1/ipaddresses/{ip_id}", method="DELETE"
        ).respond_with_data(status=204)
        ctx = nullcontext()
    else:
        ctx = pytest.raises(CliWarning)
        msg = "not owned"

    if ipversion == 4:
        func = host.a_remove
    elif ipversion == 6:
        func = host.aaaa_remove
    else:
        raise ValueError(f"Invalid IP version: {ipversion}")

    with ctx as exc_info:
        func(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("alias", ["bar.example.com"])
@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize("host_has_cname", [True, False])
@pytest.mark.parametrize("cname_in_use", [True, False])
def test_cname_add(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_zone: Dict[str, Any],
    name: str,
    alias: str,
    force: bool,
    host_has_cname: bool,
    cname_in_use: bool,
) -> None:
    _host_info_by_name_handler(httpserver, sample_host)
    alias_info = sample_host.copy()
    alias_info["name"] = alias

    if host_has_cname:
        _host_info_by_name_handler(httpserver, alias_info, cname=True)
    else:
        _host_info_by_name_handler(httpserver, None, cname=True, hostname=alias)

    if cname_in_use:
        results = [sample_host]
    else:
        results = []

    cname_exists_handler(httpserver, results)
    zoneinfo_for_hostname_handler(httpserver, alias, sample_zone)

    httpserver.expect_oneshot_request(
        "/api/v1/cnames/", method="POST"
    ).respond_with_data(status=201)

    args = Namespace(name=name, alias=alias, force=force)
    ctx = nullcontext()
    msg = ""

    if host_has_cname:
        msg = "host"
        ctx = pytest.raises(CliError)
    elif cname_in_use:
        msg = "already in use"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.cname_add(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("alias", ["bar.example.com"])
@pytest.mark.parametrize("host_has_cname", [True, False])
def test_cname_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    alias: str,
    host_has_cname: bool,
) -> None:
    # Remove or set cname based on parametrization
    if host_has_cname:
        sample_host["cnames"][0]["name"] = alias
    else:
        sample_host["cnames"] = []
    _host_info_by_name_handler(httpserver, sample_host)

    # Delete CNAME handler
    httpserver.expect_oneshot_request(
        f"/api/v1/cnames/{alias}", method="DELETE"
    ).respond_with_data(status=204)

    # Run the command and verify
    args = Namespace(name=name, alias=alias)
    ctx = nullcontext()
    msg = ""

    if not host_has_cname:
        msg = "any cname records"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.cname_remove(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("cname", ["bar.example.com"])
@pytest.mark.parametrize("hostname", ["foo.example.com"])
@pytest.mark.parametrize("host_has_cname", [True, False])
def test_cname_replace(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    cname: str,
    hostname: str,
    host_has_cname: bool,
) -> None:
    other_host = sample_host.copy()
    other_host["name"] = cname

    if not host_has_cname:
        other_host["id"] = sample_host["id"] + 1  # make sure ID is different

    _host_info_by_name_handler(httpserver, other_host)
    _host_info_by_name_handler(httpserver, sample_host)

    # Delete CNAME handler
    httpserver.expect_oneshot_request(
        f"/api/v1/cnames/{cname}", method="PATCH"
    ).respond_with_data(status=204)

    # Run the command and verify
    args = Namespace(cname=cname, host=hostname)
    ctx = nullcontext()
    msg = ""

    if host_has_cname:
        msg = "already points to"
        ctx = pytest.raises(CliError)

    with ctx as exc_info:
        host.cname_replace(args)

    if exc_info:
        assert msg in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("cpu", ["x86"])
@pytest.mark.parametrize("os", ["Win"])
@pytest.mark.parametrize("has_hinfo", [True, False])
def test_hinfo_add(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    cpu: str,
    os: str,
    has_hinfo: str,
) -> None:
    if not has_hinfo:
        sample_host["hinfo"] = None
    _host_info_by_name_handler(httpserver, sample_host)

    expect_data = f"host={sample_host['id']}&cpu={cpu}&os={os}"
    httpserver.expect_oneshot_request(
        "/api/v1/hinfos/",
        method="POST",
        data=expect_data,
    ).respond_with_data(status=201)

    args = Namespace(name=name, cpu=cpu, os=os)

    ctx = nullcontext()
    msg = ""

    if has_hinfo:
        msg = "already has hinfo"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.hinfo_add(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("has_hinfo", [True, False])
def test_hinfo_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    has_hinfo: str,
) -> None:
    if not has_hinfo:
        sample_host["hinfo"] = None
    _host_info_by_name_handler(httpserver, sample_host)

    httpserver.expect_oneshot_request(
        f"/api/v1/hinfos/{sample_host['id']}",
        method="DELETE",
    ).respond_with_data(status=204)

    args = Namespace(name=name)

    ctx = nullcontext()
    msg = ""

    if not has_hinfo:
        msg = "already has no hinfo"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.hinfo_remove(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("loc", ["Arctic"])
@pytest.mark.parametrize("has_loc", [True, False])
def test_loc_add(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    loc: str,
    has_loc: str,
) -> None:
    if not has_loc:
        sample_host["loc"] = None
    _host_info_by_name_handler(httpserver, sample_host)

    expect_data = f"host={sample_host['id']}&loc={loc}"
    httpserver.expect_oneshot_request(
        "/api/v1/locs/",
        method="POST",
        data=expect_data,
    ).respond_with_data(status=201)

    args = Namespace(name=name, loc=loc)

    ctx = nullcontext()
    msg = ""

    if has_loc:
        msg = "already has loc"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.loc_add(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("has_loc", [True, False])
def test_loc_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    name: str,
    has_loc: bool,
) -> None:
    if not has_loc:
        sample_host["loc"] = None
    _host_info_by_name_handler(httpserver, sample_host)

    httpserver.expect_oneshot_request(
        f"/api/v1/locs/{sample_host['id']}",
        method="DELETE",
    ).respond_with_data(status=204)

    args = Namespace(name=name)

    ctx = nullcontext()
    msg = ""

    if not has_loc:
        msg = "already has no loc"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.loc_remove(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("priority", [10])
@pytest.mark.parametrize("mx", ["mx.example.com"])
@pytest.mark.parametrize("has_mx", [True, False])
def test_mx_add(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_mx: Dict[str, Any],
    name: str,
    priority: int,
    mx: str,
    has_mx: bool,
) -> None:
    if not has_mx:
        sample_host["mx"] = None
    else:
        sample_mx.update({"priority": priority, "mx": mx})
        sample_host["mx"] = [sample_mx]
    _host_info_by_name_handler(httpserver, sample_host)

    expect_data = f"host={sample_host['id']}&priority={priority}&mx={mx}"
    httpserver.expect_oneshot_request(
        "/api/v1/mxs/",
        method="POST",
        data=expect_data,
    ).respond_with_data(status=201)

    args = Namespace(name=name, priority=priority, mx=mx)

    ctx = nullcontext()
    msg = ""

    if has_mx:
        msg = "already has that mx"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.mx_add(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()


@pytest.mark.parametrize("name", ["foo.example.com"])
@pytest.mark.parametrize("priority", [10])
@pytest.mark.parametrize("mx", ["mx.example.com"])
@pytest.mark.parametrize("has_mx", [True, False])
def test_mx_remove(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    sample_mx: Dict[str, Any],
    name: str,
    priority: int,
    mx: str,
    has_mx: bool,
) -> None:
    if not has_mx:
        sample_host["mx"] = None
    else:
        sample_mx.update({"priority": priority, "mx": mx})
        sample_host["mx"] = [sample_mx]
    _host_info_by_name_handler(httpserver, sample_host)

    httpserver.expect_oneshot_request(
        f"/api/v1/mxs/{sample_mx['id']}",
        method="DELETE",
    ).respond_with_data(status=204)

    args = Namespace(name=name, priority=priority, mx=mx)

    ctx = nullcontext()
    msg = ""

    if not has_mx:
        msg = "no MX"
        ctx = pytest.raises(CliWarning)

    with ctx as exc_info:
        host.mx_remove(args)

    if exc_info:
        assert msg.lower() in exc_info.exconly().lower()