"""Module that defines HTTPServer handlers for functions used by multiple tests.

Since the httpserver fixture passed to these functions is function-scoped,
it is destroyed after each test. Therefore, we don't need to worry about
leaking state between tests or having to clean up afterwards.

See: conftest.py:httpserver fixture.
"""

from typing import Any, Dict, List, Optional
from pytest_httpserver import HTTPServer

from mreg_cli.util import format_mac


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


# def _get_ip_from_args_handler(
#     httpserver: HTTPServer,
#     ip: str,

#     status: int = 200,
# ) -> None:
#     httpserver.expect_oneshot_request(
#         "/api/v1/ip/",
#     ).respond_with_json({"ip": ip}, status=status)