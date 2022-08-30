"""Module that defines HTTPServer handlers for functions used by multiple tests.

Since the httpserver fixture passed to these functions is function-scoped,
it is destroyed after each test. Therefore, we don't need to worry about
leaking state between tests or having to clean up afterwards.

See: conftest.py:httpserver fixture.
"""

from typing import Any, Dict, List, Optional
from pytest_httpserver import HTTPServer
import urllib.parse

from mreg_cli.util import clean_hostname, format_mac
from mreg_cli import util

###############
# Module: util
###############

def cname_exists_handler(
    httpserver: HTTPServer,
    results: List[Dict[str, Any]],
    next: Optional[str],
    query_string: Optional[str] = None,
) -> None:
    """Handler for util.cname_exists()."""
    httpserver.expect_oneshot_request(
        "/api/v1/cnames/",
        query_string=query_string,
    ).respond_with_json({"results": results, "next": next})


def get_network_handler(
    httpserver: HTTPServer,
    sample_network: Dict[str, Any],
    ip: str,
    is_network: bool,
    status: int = 200,
) -> None:
    """Handler for util.get_network()."""
    # If we already have a network, use it.
    if not is_network:
        get_network_by_ip_handler(httpserver, ip, sample_network, status=status)
    else:
        httpserver.expect_oneshot_request(
            f"/api/v1/networks/{urllib.parse.quote(ip)}", method="GET"
        ).respond_with_json(sample_network, status=status)


def get_network_by_ip_handler(
    httpserver: HTTPServer,
    ip: str,
    sample_network: Dict[str, Any],
    status: int = 200,
) -> None:
    """Handler for util.get_network_by_ip()."""
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/ip/{ip}", method="GET"
    ).respond_with_json(sample_network, status=status)


###############
# Module: host
###############


def zoneinfo_for_hostname_handler(
    httpserver: HTTPServer,
    hostname: str,
    sample_zone: Dict[str, Any],
    status: int = 200,
) -> None:
    """Handler for host.zoneinfo_for_hostname()."""
    httpserver.expect_oneshot_request(
        f"/api/v1/zones/forward/hostname/{hostname}",
    ).respond_with_json(sample_zone, status=status)


def _host_info_by_name_handler(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    *,
    cname: bool = False,
    is404: bool = False,
    hostname: Optional[str] = None,  # override hostname in sample_host
) -> None:
    if hostname is None:
        pname = urllib.parse.quote(sample_host["name"])
    else:
        pname = urllib.parse.quote(hostname)

    # No match (404)
    if is404:
        httpserver.expect_oneshot_request(
            f"/api/v1/hosts/{pname}", method="GET"
        ).respond_with_data(status=404)

    # Exact match
    elif not cname:
        httpserver.expect_oneshot_request(
            f"/api/v1/hosts/{pname}", method="GET"
        ).respond_with_json(
            sample_host,
        )

    # Match via CNAME lookup
    else:
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
                "results": [sample_host],
                "next": None,
            },
        )


def resolve_input_name_handler(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    hostname: str,
    status: int = 200,
) -> None:
    """Handler for host.resolve_input_name()."""
    h = clean_hostname(hostname)
    httpserver.expect_oneshot_request(
        f"/api/v1/hosts/", method="GET", query_string=f"name={h}"
    ).respond_with_json({"results": [sample_host], "next": None}, status=status)


def assoc_mac_to_ip_handler(
    httpserver: HTTPServer,
    mac: str,
    ip: Dict[str, Any],
    get_status: int = 200,
    patch_status: int = 200,
    results: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Handler for host.assoc_mac_to_ip()."""
    if results is None:
        results = []

    # Make sure the MAC address is formatted correctly.
    mac_fmt = format_mac(mac)

    # Fetching IP addresses associated with a MAC address.
    httpserver.expect_oneshot_request(
        "/api/v1/ipaddresses/",
        query_string={"macaddress": mac_fmt, "ordering": "ipaddress"},
    ).respond_with_json({"results": results, "next": None}, status=get_status)

    # Associate MAC address with IP address.
    httpserver.expect_oneshot_request(
        f"/api/v1/ipaddresses/{ip['id']}",
        method="PATCH",
        # query_string={"macaddress": mac_fmt},
    ).respond_with_data(status=patch_status)


def _get_ip_from_args_handler(
    httpserver: HTTPServer,
    sample_network: Dict[str, Any],
    sample_host: Dict[str, Any],
    ip: str,
    is_network: bool,
    ip_in_use: bool,
    ip_reserved: bool,
    network_frozen: bool,
) -> None:
    """Sets up the HTTP handlers required to test host._get_ip_from_args()
    depending on the parameters passed in."""
    # Handler for retrieving host by IP address
    if not is_network:
        results = [sample_host] if ip_in_use else []
        httpserver.expect_request(
            "/api/v1/hosts/",
            query_string=f"ipaddresses__ipaddress={urllib.parse.quote(ip)}",
        ).respond_with_json({"results": results, "next": None})
    else:
        # TODO: move to get_network_first_unused_handler
        unused = sample_host["ipaddresses"][0]["ipaddress"]
        httpserver.expect_request(
            f"/api/v1/networks/{ip}/first_unused", method="GET"
        ).respond_with_json(unused)

    # Set frozen status
    sample_network["frozen"] = network_frozen

    # Init handler for util.get_network() calls
    get_network_handler(httpserver, sample_network, ip=ip, is_network=is_network)

    # TODO: use get_network_reserved_ips handler here instead
    reserved_ips = [ip] if ip_reserved else []
    n = sample_network["network"]  # not quite right for IPv6
    httpserver.expect_oneshot_request(
        f"/api/v1/networks/{n}/reserved_list", method="GET"
    ).respond_with_json({"results": reserved_ips, "next": None})
