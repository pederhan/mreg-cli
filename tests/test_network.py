from argparse import Namespace
from typing import Any, Callable, Dict, List, Optional, Union

import pytest
from _pytest.capture import CaptureFixture
from mreg_cli import network, util
from mreg_cli.exceptions import CliWarning
from pytest_httpserver import HTTPServer


def _get_pad_len(prefix: str, padding: int) -> int:
    return padding - len(prefix)


@pytest.mark.parametrize("info", ["192.168.1.0/24", 1234, True])
def test_print_network(
    info: Union[str, int, bool], capsys: CaptureFixture[str]
) -> None:
    PADDING = 25
    PREFIX = "Network:"

    network.print_network(info, "Network:", PADDING)

    out, err = capsys.readouterr()
    pad_len = _get_pad_len(PREFIX, PADDING)
    assert out == PREFIX + (pad_len * " ") + str(info) + "\n"
    assert err == ""


@pytest.mark.parametrize("location", ["foo-location", None])
@pytest.mark.parametrize("category", ["foo-category", None])
@pytest.mark.parametrize("frozen", [True, False])
@pytest.mark.parametrize(
    "network_cidr, network_overlaps", [("10.0.2.0/24", False), ("10.0.1.64/26", True)]
)
def test_create(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    location: Optional[str],
    category: Optional[str],
    frozen: bool,
    network_cidr: str,
    network_overlaps: bool,
) -> None:
    """Tests network.create() with most arg variations."""
    if location:
        util.location_tags = [location]
    if category:
        util.category_tags = [category]

    args = Namespace(
        network=network_cidr,
        desc="foo-description",
        vlan="1",
        category=category,
        location=location,
        frozen=frozen,
    )

    # make sure response's network is the expected value for this test
    sample_network["network"] = "10.0.1.0/24"

    httpserver.expect_oneshot_request(
        "/api/v1/networks/", method="GET"
    ).respond_with_json({"results": [sample_network], "next": None})

    # If not overlapping, expect a POST request
    if not network_overlaps:
        httpserver.expect_oneshot_request(
            "/api/v1/networks/", method="POST"
        ).respond_with_data(status=201)
        network.create(args)
        out, err = capsys.readouterr()
        assert network_cidr in out
    else:
        # If overlapping, expect a warning
        with pytest.raises(CliWarning) as exc_info:
            network.create(args)
        assert "overlap" in exc_info.exconly().lower()


@pytest.mark.parametrize(
    "input,expected,is_network,valid",
    [
        # Networks (valid)
        ("10.0.1.0/24", "10.0.1.0/24", True, True),
        ("10.0.1.0/24/", "10.0.1.0/24", True, True),
        # IPs (valid)
        ("10.0.1.0", "10.0.1.0/24", False, True),
        ("10.0.1.0/", "10.0.1.0/24", False, True),
        # Out of range (invalid)
        ("256.0.1.0/24/", "", True, False),
        ("256.0.1.0/24", "", True, False),
        ("256.0.1.0", "", False, False),
        ("256.0.1.0/", "", False, False),
    ],
)
def test_get_network_range_from_input(
    httpserver: HTTPServer,
    sample_network: Dict[str, Any],
    input: str,
    expected: str,
    is_network: bool,
    valid: bool,
) -> None:
    # Setup handlers if input is an IP
    if not is_network:
        _setup_get_network_handlers(
            httpserver, sample_network, is_network, input.strip("/")
        )
    if valid:
        assert network.get_network_range_from_input(input) == expected
    else:
        with pytest.raises(CliWarning):
            network.get_network_range_from_input(input)


@pytest.mark.skip(
    "Mostly covered by test_utils.test_get_network_unused_list(). "
    "TODO: be able to test both functions without duplicating too much code."
)
def test_list_unused_addresses() -> None:
    pass


def test_list_used_addresses(
    httpserver: HTTPServer, capsys: CaptureFixture[str]
) -> None:
    # TODO: test with no used non-ptr and no used ptr addresses
    used_hosts = {
        "10.0.1.2": ["two.example.com", "two-two.example.com"],
        "10.0.1.3": ["three.example.com"],
    }
    used_hosts_ptr = {
        "10.0.1.4": ["four.example.com"],
        "10.0.1.5": ["five.example.com"],
    }

    args = Namespace(network="10.0.1.0/24")

    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{args.network}/used_host_list", method="GET"
    ).respond_with_json(used_hosts)

    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{args.network}/ptroverride_host_list", method="GET"
    ).respond_with_json(used_hosts_ptr)

    network.list_used_addresses(args)
    out, err = capsys.readouterr()
    out = out.lower()

    # These assertions need some work
    for host in used_hosts:
        assert host in out
        assert "no" in out

    for host in used_hosts_ptr:
        assert host in out
        assert "ptr" in out


@pytest.mark.parametrize("used", [["10.0.1.1", "10.0.1."], []])
@pytest.mark.parametrize("force", [True, False])
def test_remove(
    httpserver: HTTPServer, capsys: CaptureFixture[str], used: List[str], force: bool
) -> None:
    args = Namespace(network="10.0.1.0/24", force=force)

    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{args.network}/used_list", method="GET"
    ).respond_with_json(used)

    if used or not force:
        with pytest.raises(CliWarning) as exc_info:
            network.remove(args)
        if used:
            assert "in use" in exc_info.exconly().lower()
        else:
            assert "force" in exc_info.exconly().lower()
    else:
        httpserver.expect_oneshot_request(
            f"/api/v1/networks/{args.network}", method="DELETE"
        ).respond_with_data(status=200)
        network.remove(args)
        out, err = capsys.readouterr()
        assert args.network in out
        assert err == ""


netfunc_decorator = pytest.mark.parametrize(
    "input,is_network", [("10.0.1.2", False), ("10.0.1.0/24", True)]
)


@netfunc_decorator
def test_add_excluded_range(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    args = Namespace(network=input, start_ip="10.0.1.2", end_ip="10.0.1.10")
    net = _setup_get_network_handlers(httpserver, sample_network, is_network, input)

    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{net}/excluded_ranges/", method="POST"
    ).respond_with_data(status=200)
    network.add_excluded_range(args)
    out, err = capsys.readouterr()
    assert net in out


@netfunc_decorator
def test_remove_excluded_range(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:

    start_ip = sample_network["excluded_ranges"][0]["start_ip"]
    end_ip = sample_network["excluded_ranges"][0]["end_ip"]
    range_id = sample_network["excluded_ranges"][0]["id"]

    args = Namespace(
        network=input,
        start_ip=start_ip,
        end_ip=end_ip,
    )
    net = _setup_get_network_handlers(httpserver, sample_network, is_network, input)

    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{net}/excluded_ranges/{range_id}", method="DELETE"
    ).respond_with_data(status=200)
    network.remove_excluded_range(args)
    out, err = capsys.readouterr()
    assert net in out


@netfunc_decorator
def test_set_category(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    util.category_tags = ["foo", "bar"]
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_category,
        category="bar",
    )
    with pytest.raises(CliWarning):
        _do_test_set_network_(
            httpserver,
            capsys,
            sample_network,
            input,
            is_network,
            func=network.set_category,
            category="baz",
        )


@netfunc_decorator
def test_set_description(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_description,
        description="foo-description",
    )


@netfunc_decorator
def test_set_dns_delegated(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_dns_delegated,
    )


@netfunc_decorator
def test_set_frozen(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_frozen,
    )


@netfunc_decorator
def test_set_location(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    util.location_tags = ["foo", "bar"]
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_location,
        location="foo",
    )
    with pytest.raises(CliWarning):
        _do_test_set_network_(
            httpserver,
            capsys,
            sample_network,
            input,
            is_network,
            func=network.set_location,
            location="baz",
        )


@netfunc_decorator
def test_set_reserved(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_reserved,
        number=123,
    )


@netfunc_decorator
def test_set_vlan(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.set_vlan,
        vlan=123,
    )


@netfunc_decorator
def test_unset_dns_delegated(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.unset_dns_delegated,
    )


@netfunc_decorator
def test_unset_frozen(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
) -> None:
    _do_test_set_network_(
        httpserver,
        capsys,
        sample_network,
        input,
        is_network,
        func=network.unset_frozen,
    )


def _do_test_set_network_(
    httpserver: HTTPServer,
    capsys: CaptureFixture[str],
    sample_network: Dict[str, Any],
    input: str,
    is_network: bool,
    func: Callable[[Namespace], None],
    **kwargs: Any,
) -> None:
    """Helper function for testing the various network.set_*() functions.

    NOTE: does not currently check the body of the PATCH request!
    """

    args = Namespace(network=input, **kwargs)
    net = _setup_get_network_handlers(httpserver, sample_network, is_network, input)

    # Network update
    httpserver.expect_request(
        f"/api/v1/networks/{net}", method="PATCH"
    ).respond_with_data(status=200)

    func(args)

    out, err = capsys.readouterr()
    assert net in out


def _setup_get_network_handlers(
    httpserver: HTTPServer,
    sample_network: Dict[str, Any],
    is_network: bool,
    input: str,
) -> str:
    """Sets up HTTP handlers required for util.get_network()."""
    if is_network:
        sample_network["network"] = input
    net = sample_network["network"]

    # IP lookup (fetches network for IP)
    # Only used if input is an IP
    if not is_network:
        httpserver.expect_oneshot_request(
            f"/api/v1/networks/ip/{input}", method="GET"
        ).respond_with_json(sample_network)

    # Network lookup (redundant?)
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{net}", method="GET"
    ).respond_with_json(sample_network)
    return net
