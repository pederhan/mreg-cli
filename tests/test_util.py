import os
import urllib.parse
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pytest
import requests
from _pytest.capture import CaptureFixture
from mreg_cli import util
from mreg_cli.exceptions import CliError, CliWarning, HostNotFoundWarning
from pytest_httpserver import HTTPServer

from .handlers import cname_exists_handler


def test_set_config() -> None:
    util.set_config({"foo": "bar"})
    assert util.config == {"foo": "bar"}


def test_error(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        util.error("foo")
    assert exc_info.value.code == os.EX_UNAVAILABLE
    # error() does not include a message with its SystemExit exception
    # so we need to check the captured output (because it uses print() then sys.exit())
    out, err = capsys.readouterr()
    assert err == "ERROR: foo\n"


def test_host_exists(
    httpserver: HTTPServer,
) -> None:
    # Match
    httpserver.expect_oneshot_request("/api/v1/hosts/", method="GET").respond_with_json(
        {
            "results": [{"name": "foo"}],
            "next": None,
        },
    )
    assert util.host_exists("foo")

    # No match
    httpserver.expect_oneshot_request("/api/v1/hosts/", method="GET").respond_with_json(
        {
            "results": [],
            "next": None,
        },
    )
    assert not util.host_exists("qux")

    # Wrong match
    with pytest.raises(CliError) as exc_info:
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/", method="GET"
        ).respond_with_json(
            {
                "results": [{"name": "foo"}],
                "next": None,
            },
        )
        util.host_exists("bar")
    assert "when searched for" in exc_info.exconly().lower()  # TODO: make more specific


def test_resolve_ip(httpserver: HTTPServer) -> None:
    # TODO: add IPv4Address and IPv6Address support?
    def _qstring(ip: str) -> str:
        return f"ipaddresses__ipaddress={ip}"

    IP = "192.168.1.2"

    # Match
    httpserver.expect_oneshot_request(
        "/api/v1/hosts/", method="GET", query_string=_qstring(IP)
    ).respond_with_json(
        {
            "results": [{"name": "foo"}],
            "next": None,
        },
    )
    assert util.resolve_ip(IP) == "foo"

    # No match
    with pytest.raises(HostNotFoundWarning) as exc_info:
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/", method="GET", query_string=_qstring(IP)
        ).respond_with_json(
            {
                "results": [],
                "next": None,
            },
        )
        util.resolve_ip(IP)
    assert "belong to any host" in exc_info.exconly().lower()

    # >1 match
    with pytest.raises(CliError) as exc_info:  # type: ignore
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/", method="GET", query_string=_qstring(IP)
        ).respond_with_json(
            {
                "results": [{"name": "foo"}, {"name": "bar"}],
                "next": None,
            },
        )
        util.resolve_ip(IP)
    assert (
        "multiple matches for ip" in exc_info.exconly().lower()
    )  # TODO: make more specific


def test_host_info_by_name(httpserver: HTTPServer) -> None:
    # TODO: make more comprehensive without re-creating test__host_info_by_name() below
    name = "foo-bar"
    cleaned = util.clean_hostname(name)  # make sure we get URL right

    # Exact match
    resp = {"name": "foo"}
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{cleaned}", method="GET"
    ).respond_with_json(resp)

    assert util.host_info_by_name(name) == resp

    # NOTE: we do NOT test with follow_cname=True here,
    # as we already have a test for that in test__host_info_by_name()
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{cleaned}", method="GET"
    ).respond_with_data(status=404)
    with pytest.raises(HostNotFoundWarning) as exc_info:
        util.host_info_by_name(name, follow_cname=False)
    assert "not found" in exc_info.exconly().lower()


def test__host_info_by_name(httpserver: HTTPServer) -> None:
    name = "foo-bar"
    pname = urllib.parse.quote(name)

    # Exact match
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{pname}", method="GET"
    ).respond_with_json(
        {
            "name": "foo",
        },
    )
    host = util._host_info_by_name(name, follow_cname=False)
    assert host == {"name": "foo"}

    # Match via CNAME lookup
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{pname}", method="GET"
    ).respond_with_data(
        status=404
    )  # Set up 404 response to fall back on CNAME lookup

    # The handler for the CNAME lookup
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/", method="GET", query_string=f"cnames__name={pname}"
    ).respond_with_json(
        {
            "results": [{"name": "foo"}],
            "next": None,
        },
    )
    host_cname = util._host_info_by_name(name, follow_cname=True)
    assert host_cname == {"name": "foo"}

    # No match
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{pname}", method="GET"
    ).respond_with_data(status=404)
    assert util._host_info_by_name(name, follow_cname=False) is None


def test__cname_info_by_name(httpserver: HTTPServer) -> None:
    name = "foo"
    httpserver.expect_oneshot_request(
        f"/api/v1/cnames/", method="GET", query_string={"name": name}
    ).respond_with_json(
        {
            "results": [{"name": "foo"}],
            "next": None,
        }
    )
    assert util._cname_info_by_name(name) == {"name": "foo"}

    # Multiple and no match yields None
    for res in [[{"name": "foo"}, {"name": "bar"}], []]:
        httpserver.expect_oneshot_request(
            f"/api/v1/cnames/", method="GET", query_string={"name": name}
        ).respond_with_json({"results": res, "next": None})
        assert util._cname_info_by_name(name) is None


def test__srv_info_by_name(httpserver: HTTPServer) -> None:
    name = "foo"
    httpserver.expect_oneshot_request(
        f"/api/v1/srvs/", method="GET", query_string={"name": name}
    ).respond_with_json(
        {
            "results": [{"name": "foo"}],
            "next": None,
        }
    )
    assert util._srv_info_by_name(name) == {"name": "foo"}

    # Multiple and no match yields None
    for res in [[{"name": "foo"}, {"name": "bar"}], []]:
        httpserver.expect_oneshot_request(
            f"/api/v1/srvs/", method="GET", query_string={"name": name}
        ).respond_with_json({"results": res, "next": None})
        assert util._srv_info_by_name(name) is None


@pytest.mark.parametrize(
    "hostinfo,cnameinfo,srvinfo",
    [
        ({"name": "foo"}, None, None),
        (None, {"name": "foo"}, None),
        (None, None, {"name": "foo"}),
        (None, None, None),
    ],
)
def test_get_info_by_hostname(
    hostinfo: Optional[dict],
    cnameinfo: Optional[dict],
    srvinfo: Optional[dict],
    httpserver: HTTPServer,
) -> None:
    name = "foo"
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/{name}", method="GET"
    ).respond_with_json(hostinfo)
    httpserver.expect_oneshot_request(
        f"/api/v1/cnames/", method="GET", query_string={"name": name}
    ).respond_with_json(
        {
            "results": [cnameinfo],
            "next": None,
        }
    )
    httpserver.expect_oneshot_request(
        f"/api/v1/srvs/", method="GET", query_string={"name": name}
    ).respond_with_json(
        {
            "results": [srvinfo],
            "next": None,
        }
    )
    if any((hostinfo, cnameinfo, srvinfo)):
        category, info = util.get_info_by_name(name)
        if hostinfo:
            assert category == "host"
            assert info == hostinfo
        elif cnameinfo:
            assert category == "cname"
            assert info == cnameinfo
        elif srvinfo:
            assert category == "srv"
            assert info == srvinfo
        else:
            assert False, "Should be unreachable"
    else:
        with pytest.raises(HostNotFoundWarning) as exc_info:
            util.get_info_by_name(name)
        assert "not found" in exc_info.exconly().lower()


def test_get_network_by_ip(
    httpserver: HTTPServer, sample_network: Dict[str, Any]
) -> None:
    IP = "10.0.1.20"

    # Match with valid IP
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/ip/{urllib.parse.quote(IP)}", method="GET"
    ).respond_with_json(sample_network)

    resp = util.get_network_by_ip(IP)
    assert resp == sample_network

    # No match with valid IP
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/ip/{urllib.parse.quote(IP)}", method="GET"
    ).respond_with_data(status=404)

    resp = util.get_network_by_ip(IP)
    assert resp == {}

    # Invalid IP
    for invalid_ip in ["1234", "10.0.1.256", "", " ", None]:
        # Can only test strings, because urllib.parse.quote() will raise a
        # TypeError if the input is not a string (or None)
        with pytest.raises(CliWarning) as exc_info:
            util.get_network_by_ip(invalid_ip)  # type: ignore
        assert "not a valid ip address" in exc_info.exconly().lower()


def test_ip_in_mreg_net(httpserver: HTTPServer, sample_network: Dict[str, Any]) -> None:
    # Match with valid IP
    IP = "10.0.1.20"
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/ip/{urllib.parse.quote(IP)}", method="GET"
    ).respond_with_json(sample_network)

    assert util.ip_in_mreg_net(IP) == True  # explicit comparison


def test_set_file_permissions(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    # TODO: Add PermissionError mocking
    #       Right now we never encounter the PermissionError branch

    # Test with a file that exists
    f = tmp_path / "test"
    f.touch()
    util.set_file_permissions(f, 0o600)
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

    # Test with a file that does not exist
    f = tmp_path / "test2"
    util.set_file_permissions(f, 0o600)
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

    # Test with a directory
    d = tmp_path / "test3"
    d.mkdir()
    util.set_file_permissions(d, 0o755)
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


@pytest.mark.parametrize(
    "hostname,valid",
    [
        ("foo", True),
        ("foo.example.com", True),
        ("foo.example.com.", True),  # Trailing dot is removed
        ("foo.example.com/", False),  # trailing slash
        ("", False),  # empty string
        (123, False),  # wrong type (int)
        (None, False),  # wrong type (None)
        (object(), False),  # wrong type (object)
    ],
)
@pytest.mark.parametrize("as_bytes", [True, False])
def test_clean_hostname(
    hostname: Union[str, bytes], valid: bool, as_bytes: bool
) -> None:
    # TODO: might be worth testing without config["domain"] set
    util.config["domain"] = "example.com"  # make sure domain is set in config

    # Test with hostname as bytes object
    if as_bytes and isinstance(hostname, str):
        hostname = hostname.encode()

    if valid:
        assert util.clean_hostname(hostname) == "foo.example.com"
    else:
        with pytest.raises(CliWarning) as exc_info:
            util.clean_hostname(hostname)
        assert "invalid input" in exc_info.exconly().lower()

    # NOTE: we do NOT test "foo.example." (counts as valid but probably shouldn't be)
    #       The problem:
    #           >>> clean_hostname("foo.example.") == "foo.example."


def test_update_token(
    capsys: CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    httpserver: HTTPServer,
    tmp_path: Path,
) -> None:
    def mock_prompt(*args, **kwargs) -> str:
        return "password"

    # Mock stdin password input
    monkeypatch.setattr("mreg_cli.util.prompt", mock_prompt)

    token_file = tmp_path / "mreg_token"
    util.mreg_auth_token_file = str(token_file)

    util.username = "foo"

    httpserver.expect_oneshot_request(
        "/api/token-auth/",
        method="POST",
        data="username=foo&password=password",
    ).respond_with_json({"token": "test-token"})
    util.update_token()
    assert util.session.headers["Authorization"] == "Token test-token"
    assert oct(token_file.stat().st_mode & 0o600) == "0o600"  # better way to do this?
    assert token_file.read_text() == "foo¤test-token"

    # Test with invalid password
    token_file_pre = token_file.read_text()
    token_header_pre = util.session.headers["Authorization"]
    httpserver.expect_oneshot_request(
        "/api/token-auth/",
        method="POST",
        data="username=foo&password=password",
    ).respond_with_json({"non_field_errors": ["Invalid username/password"]}, status=400)
    with pytest.raises(SystemExit) as exc_info:
        util.update_token()

    out, err = capsys.readouterr()
    assert "Invalid username/password" in err
    # Assert token is unchanged (file and header)
    assert token_file.read_text() == token_file_pre
    assert util.session.headers["Authorization"] == token_header_pre

    # Other error
    token_file_pre = token_file.read_text()
    token_header_pre = util.session.headers["Authorization"]
    httpserver.expect_oneshot_request(
        "/api/token-auth/",
        method="POST",
        data="username=foo&password=password",
    ).respond_with_json({"error": "some_error"}, status=400)
    with pytest.raises(SystemExit) as exc_info:
        util.update_token()
    out, err = capsys.readouterr()
    assert "some_error" in err
    # Assert token is unchanged (file and header)
    assert token_file.read_text() == token_file_pre
    assert util.session.headers["Authorization"] == token_header_pre


@pytest.mark.parametrize(
    "status_code,reason,expect_ok", [(200, "OK", True), (400, "Bad Request", False)]
)
def test_result_check(status_code: int, reason: str, expect_ok: bool) -> None:
    result = requests.Response()
    result.status_code = status_code
    result.reason = reason
    result._content = b'{"message": "test"}'

    method = "GET"
    url = "http://example.com/some/resource"
    if expect_ok:
        util.result_check(result, method, url)
    else:
        with pytest.raises(CliWarning) as exc_info:
            util.result_check(result, method, url)
        exc_msg = exc_info.exconly().lower()
        assert method.lower() in exc_msg
        assert url in exc_msg
        # TODO: improve JSON checking
        assert "message" in exc_msg
        assert "test" in exc_msg


def test_get(httpserver: HTTPServer) -> None:
    endpoint = "/api/test"
    response = {"foo": "bar"}
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
    ).respond_with_json(response)

    resp = util.get(endpoint)
    assert resp.json() == response


def test_get_list(httpserver: HTTPServer) -> None:
    endpoint = "/api/test"

    # Page 1 (no query param)
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
    ).respond_with_json({"results": [{"foo": "bar"}], "next": endpoint + "?page=2"})

    # Page 2
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
        query_string="page=2",
    ).respond_with_json({"results": [{"baz": "qux"}], "next": endpoint + "?page=3"})

    # Page 3 (no Next)
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
        query_string="page=3",
    ).respond_with_json({"results": [{"quux": "corge"}], "next": None})

    resp = util.get_list(endpoint)
    assert resp == [{"foo": "bar"}, {"baz": "qux"}, {"quux": "corge"}]


def test_get_list_ok404(httpserver: HTTPServer) -> None:
    """Tests get_list(..., ok404=True), where page 2 returns 404."""
    endpoint = "/api/test"
    # Page 1
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
    ).respond_with_json({"results": [{"foo": "bar"}], "next": endpoint + "?page=2"})

    # Page 2 (404)
    httpserver.expect_oneshot_request(
        endpoint,
        method="GET",
        query_string="page=2",
    ).respond_with_data(status=404)
    resp = util.get_list(endpoint, ok404=True)
    assert resp == [{"foo": "bar"}]


def test_post(httpserver: HTTPServer) -> None:
    endpoint = "/api/test"
    data = {"foo": "bar"}
    response = {"baz": "gux"}

    # TODO: add non-JSON test

    httpserver.expect_oneshot_request(
        endpoint,
        method="POST",
        json=data,
    ).respond_with_json(response)

    resp = util.post(endpoint, data, use_json=True)
    assert resp is not None
    assert resp.json() == response


def test_patch(httpserver: HTTPServer) -> None:
    endpoint = "/api/test"
    data = {"foo": "bar"}
    response = {"baz": "gux"}

    # TODO: add non-JSON test

    httpserver.expect_oneshot_request(
        endpoint,
        method="PATCH",
        json=data,
    ).respond_with_json(response)

    resp = util.patch(endpoint, data, use_json=True)
    assert resp is not None
    assert resp.json() == response


def test_delete(httpserver: HTTPServer) -> None:
    endpoint = "/api/test"
    response = {"foo": "bar"}

    # TODO: add non-JSON test

    httpserver.expect_oneshot_request(
        endpoint,
        method="DELETE",
    ).respond_with_json(response)

    resp = util.delete(endpoint)
    assert resp is not None
    assert resp.json() == response


def test_cname_exists(httpserver: HTTPServer) -> None:
    # Exists

    cname_exists_handler(
        httpserver,
        results=[{"name": "foo.example.com"}],
        next=None,
        query_string="name=foo-alias.example.com",
    )
    assert util.cname_exists("foo-alias.example.com")

    # Does not exist
    cname_exists_handler(
        httpserver,
        results=[],
        next=None,
        query_string="name=foo-alias.example.com",
    )
    assert not util.cname_exists("foo-alias.example.com")


@pytest.mark.skip(
    "Redundant. Tested by test_resolve_ip() and test_resolve_input_name()."
)
def test_resolve_name_or_ip() -> None:
    # No coverage for resolve_name_or_ip(), but the functions it calls are tested.
    # NOTE: Remove this test if we will never try to achieve 100% coverage.
    pass


def test_resolve_input_name(httpserver: HTTPServer) -> None:
    # Match
    httpserver.expect_oneshot_request(
        "/api/v1/hosts/",
        query_string="name=foo.example.com",
    ).respond_with_json({"results": [{"name": "foo.example.com"}], "next": None})

    assert util.resolve_input_name("foo.example.com") == "foo.example.com"

    # Wrong match
    with pytest.raises(AssertionError):
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/",
            query_string="name=foo.example.com",
        ).respond_with_json({"results": [{"name": "bar.example.com"}], "next": None})
        util.resolve_input_name("foo.example.com")

    # No match
    with pytest.raises(HostNotFoundWarning) as exc_info:
        httpserver.expect_oneshot_request(
            "/api/v1/hosts/",
            query_string="name=foo.example.com",
        ).respond_with_json({"results": [], "next": None})
        util.resolve_input_name("foo.example.com")
    assert "foo.example.com" in str(exc_info.value)


@pytest.mark.parametrize(
    "input,expected",
    [
        (
            # Only strings
            [
                "192.168.0.1",
                "127.0.0.1",
                "255.255.255.255",
                "10.0.0.1",
            ],
            [
                "10.0.0.1",
                "127.0.0.1",
                "192.168.0.1",
                "255.255.255.255",
            ],
        ),
        (
            # Only IPv4Address objects
            [
                IPv4Address("192.168.0.1"),
                IPv4Address("127.0.0.1"),
                IPv4Address("255.255.255.255"),
                IPv4Address("10.0.0.1"),
            ],
            [
                IPv4Address("10.0.0.1"),
                IPv4Address("127.0.0.1"),
                IPv4Address("192.168.0.1"),
                IPv4Address("255.255.255.255"),
            ],
        ),
        (
            # Mixed strings and IPv4Address objects
            [
                "192.168.0.1",
                IPv4Address("127.0.0.1"),
                "255.255.255.255",
                "10.0.0.1",
            ],
            [
                "10.0.0.1",
                IPv4Address("127.0.0.1"),
                "192.168.0.1",
                "255.255.255.255",
            ],
        ),
    ],
)
def test_ipsort(
    input: List[Union[str, IPv4Address]], expected: List[Union[str, IPv4Address]]
) -> None:
    sorted_ips = util.ipsort(input)
    assert sorted_ips == expected


def test_ipsort_mixed() -> None:
    with pytest.raises(TypeError) as exc_info:
        util.ipsort(["0a29:4249:8515:a209:6afe:7b10:19c9:40f8", "192.168.0.1"])
    assert "are not of the same version" in exc_info.exconly().lower()


def test_get_network(httpserver: HTTPServer, sample_network: Dict[str, Any]) -> None:
    # Match (IP range)
    httpserver.expect_oneshot_request("/api/v1/networks/10.0.1.0/24").respond_with_json(
        sample_network
    )
    assert util.get_network("10.0.1.0/24") == sample_network

    # Match (IP address)
    httpserver.expect_oneshot_request("/api/v1/networks/ip/10.0.1.4").respond_with_json(
        sample_network
    )
    assert util.get_network("10.0.1.4") == sample_network

    # No match (Valid IP Address)
    httpserver.expect_oneshot_request("/api/v1/networks/ip/10.0.1.4").respond_with_data(
        status=404
    )
    with pytest.raises(CliWarning) as exc_info:
        util.get_network("10.0.1.4")
    assert "ip address exists" in exc_info.exconly().lower()

    # No match (Invalid IP Address/IP Range)
    with pytest.raises(CliWarning) as exc_info:
        util.get_network("invalid")
    assert "not a valid ip range or ip address" in exc_info.exconly().lower()


def test_get_network_used_count(httpserver: HTTPServer) -> None:
    httpserver.expect_oneshot_request(
        "/api/v1/networks/10.0.1.0/24/used_count"
    ).respond_with_json(3)
    assert util.get_network_used_count("10.0.1.0/24") == 3


def test_get_network_used_list(httpserver: HTTPServer) -> None:
    used_list = ["10.0.1.2", "10.0.1.3", "10.0.1.4"]
    httpserver.expect_oneshot_request(
        "/api/v1/networks/10.0.1.0/24/used_list"
    ).respond_with_json(used_list)
    assert util.get_network_used_list("10.0.1.0/24") == used_list


def test_get_network_unused_count(httpserver: HTTPServer) -> None:
    httpserver.expect_oneshot_request(
        "/api/v1/networks/10.0.1.0/24/unused_count"
    ).respond_with_json(4)
    assert util.get_network_unused_count("10.0.1.0/24") == 4


def test_get_network_unused_list(httpserver: HTTPServer) -> None:
    unused_list = ["10.0.1.4", "10.0.1.5", "10.0.1.6", "10.0.1.7"]
    httpserver.expect_oneshot_request(
        "/api/v1/networks/10.0.1.0/24/unused_list"
    ).respond_with_json(unused_list)
    assert util.get_network_unused_list("10.0.1.0/24") == unused_list


@pytest.mark.parametrize("unused", ["10.0.2.9", None])
def test_first_unused_ip_from_network(
    unused: Optional[str], httpserver: HTTPServer
) -> None:
    # NOTE: Also tests util.get_network_first_unused()

    NETWORK = "10.0.2.0/28"
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{NETWORK}/first_unused", method="GET"
    ).respond_with_json(unused)

    network = {"network": NETWORK}
    if unused:
        assert util.first_unused_ip_from_network(network) == unused
    else:
        with pytest.raises(CliWarning) as exc_info:
            util.first_unused_ip_from_network(network)
        assert "no free addresses remaining" in exc_info.exconly().lower()


def test_get_network_reserved_ips(httpserver: HTTPServer) -> None:
    unused_list = ["10.0.1.8", "10.0.1.9", "10.0.1.10"]
    httpserver.expect_oneshot_request(
        "/api/v1/networks/10.0.1.0/24/reserved_list"
    ).respond_with_json(unused_list)
    assert util.get_network_reserved_ips("10.0.1.0/24") == unused_list


@pytest.mark.parametrize(
    "input,expected",
    [("123", 123), ("0123", 123), ("-123", -123), ("-0123", -123), ("123.456", None)],
)
def test_string_to_int(input: str, expected: int) -> None:
    error_tag = "Number"
    if expected is not None:
        assert util.string_to_int(input, error_tag) == expected
    else:
        with pytest.raises(CliWarning) as exc_info:
            util.string_to_int(input, error_tag)
        assert error_tag in exc_info.exconly()
        assert "not a valid integer" in exc_info.exconly().lower()


@pytest.mark.parametrize(
    "input,expected",
    [
        # IPv4
        ("192.168.1.1", True),
        ("192.168.1.1.", False),  # trailing dot
        ("192.168.1.256", False),  # out of range
        ("192.168.1", False),  # Missing octet
        # IPv6
        ("7593:4588:f58f:f153:167b:86da:1de3:da80", True),  # Full IPv6
        ("7593:4588::86da:1de3:da80", True),  # Single ::
        ("7593:4588::", True),  # Trailing ::
        ("::86da:1de3:da80", True),  # Leading ::
        ("7593:4588::86da::1de3:da80", False),  # Multiple ::
    ],
)
def test_is_valid_ip(input: str, expected: bool):
    assert util.is_valid_ip(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        # Valid MACs
        ("28-85-B1-60-54-DC", True),  # Dash-separated
        ("28:85:B1:60:54:DC", True),  # Colon-separated
        ("28.85.B1.60.54.DC", True),  # Dot-separated
        ("2885B16054DC", True),  # No separators
        # Invalid MACs
        ("28-85-B1-60-54-D", False),  # Dash-separated
        ("28:85:B1:60:54:D", False),  # Colon-separated
        ("28.85.B1.60.54.D", False),  # Dot-separated
        ("2885B16054D", False),  # No separators
    ],
)
def test_is_valid_mac(input: str, expected: bool):
    assert util.is_valid_mac(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        # Valid values (lower and upper bounds)
        (300, True),
        (300.0, True),
        ("300", True),
        (b"300", True),
        (68400, True),
        (68400.0, True),
        ("68400", True),
        (b"68400", True),
        # Valid values (empty, default)
        ("", True),
        ("default", True),
        # Invalid values (out of bounds)
        (299, False),
        (299.0, False),
        ("299", False),
        (b"299", False),
        (68401, False),
        (68401.0, False),
        ("68401", False),
        (b"68401", False),
        # Invalid values (can't be converted to int)
        ("300.0", False),
        ("68400.0", False),
        (b"300.0", False),
        (b"68400.0", False),
    ],
)
def test_is_valid_ttl(input: Union[str, int, float, bytes], expected: bool) -> None:
    assert util.is_valid_ttl(input) == expected  # type: ignore


@pytest.mark.parametrize(
    "input,expected",
    [
        # Valid emails
        # Not very thorough, but neither is the validation regex
        ("user@example.com", True),
        ("this-is-valid@example.com", True),
        ("this.is.valid@example.com", True),
        # Invalid emails
        ("user", False),
        ("@example.com", False),
        ("user@example", False),
        ("user.com", False),
    ],
)
@pytest.mark.parametrize("as_bytes", [False, True])
def test_is_valid_email(
    input: Union[str, bytes], expected: bool, as_bytes: bool
) -> None:
    if as_bytes and isinstance(input, str):
        input = input.encode("utf-8")
    assert util.is_valid_email(input) == expected


def test_is_valid_location_tag() -> None:
    util.location_tags = ["foo", "bar"]
    assert util.is_valid_location_tag("foo")
    assert util.is_valid_location_tag("bar")
    assert not util.is_valid_location_tag("baz")


def test_is_valid_category_tag() -> None:
    util.category_tags = ["foo", "bar"]
    assert util.is_valid_category_tag("foo")
    assert util.is_valid_category_tag("bar")
    assert not util.is_valid_category_tag("baz")


def test_format_mac() -> None:
    # NOTE: only tests valid macs
    macs = [
        "28-85-B1-60-54-DC",  # Dash-separated
        "28:85:B1:60:54:DC",  # Colon-separated
        "28.85.B1.60.54.DC",  # Dot-separated
        "2885B16054DC",  # No separators
    ]
    expected = "28:85:b1:60:54:dc"
    for mac in macs:
        assert util.format_mac(mac) == expected


@pytest.mark.parametrize(
    "param,arg,expected",
    [
        ("name", "foo*bar*", "name__startswith=foo&name__contains=bar"),
        (
            "name",
            "foo*bar*baz",
            "name__startswith=foo&name__contains=bar&name__endswith=baz",
        ),
        (
            "name",
            "foo*bar*baz*gux",
            "name__startswith=foo&name__contains=bar&name__contains=baz&name__endswith=gux",
        ),
        (
            "name",
            "foo*bar*baz*gux*",
            "name__startswith=foo&name__contains=bar&name__contains=baz&name__contains=gux",
        ),
        # Only asterisks
        ("name", "****", ""),
        # No asterisks
        ("name", "foo", "name=foo"),
    ],
)
def test_convert_wildcard_to_filter(param: str, arg: str, expected: str) -> None:
    assert util.convert_wildcard_to_filter(param, arg) == expected


@pytest.mark.parametrize(
    "param,arg,expected",
    [
        (
            "name",
            "foo*bar",
            ("name__regex", "^foobar$"),
        ),
        (
            "name",
            "foo*bar*",
            ("name__regex", "^foo.*bar.*"),
        ),
        (
            "name",
            "foo*bar*baz",
            ("name__regex", "^foo.*bar.*baz$"),
        ),
        (
            "name",
            "foo*bar*baz*gux",
            ("name__regex", "^foo.*bar.*.*baz.*gux$"),
        ),
        (
            "name",
            "foo*bar*baz*gux*",
            ("name__regex", "^foo.*bar.*.*baz.*.*gux.*"),
        ),
        # Only asterisks
        ("name", "****", ("name__regex", "")),
        # No asterisks
        ("name", "foo", ("name", "foo")),
    ],
)
def test_convert_wildcard_to_regex(param: str, arg: str, expected: str) -> None:
    assert util.convert_wildcard_to_regex(param, arg) == expected
