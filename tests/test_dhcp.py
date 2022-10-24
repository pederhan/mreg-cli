from argparse import Namespace
from typing import Any, Dict, Optional
import urllib.parse

import pytest
from mreg_cli import dhcp
from mreg_cli.exceptions import CliWarning
from mreg_cli.util import format_mac
from pytest_httpserver import HTTPServer

from .compat import nullcontext

from .handlers import (
    _dhcp_get_ip_by_arg_handler,
    _host_info_by_name_handler,
    assoc_mac_to_ip_handler,
)
from .utils import get_list_response, macaddresses


@pytest.mark.parametrize("new_mac", macaddresses())
@pytest.mark.parametrize("old_mac", macaddresses(with_none=True))
@pytest.mark.parametrize("force", [False])
def test_assoc_mac_to_ip(
    httpserver: HTTPServer,
    sample_ipaddress: Dict[str, Any],
    new_mac: str,
    old_mac: Optional[str],
    force: bool,
) -> None:
    """Test that we can associate a MAC address to an IP address."""
    sample_ipaddress["macaddress"] = old_mac

    assoc_mac_to_ip_handler(
        httpserver,
        mac=new_mac,
        ip=sample_ipaddress,
        get_status=200,
        patch_status=200,
    )

    # Expect a warning if the MAC address is already associated with an IP address.
    # and the force flag is not set.
    if old_mac and not force:
        with pytest.raises(CliWarning):
            dhcp.assoc_mac_to_ip(new_mac, sample_ipaddress, force)
    # Otherwise expect that we are able to associate the MAC address to the IP address.
    # and the new MAC address is returned.
    else:
        resp = dhcp.assoc_mac_to_ip(new_mac, sample_ipaddress, force)
        assert resp.lower() == format_mac(new_mac)


# TODO: add hostname branch testing
def test__dhcp_get_ip_by_arg(
    httpserver: HTTPServer, sample_ipaddress: Dict[str, Any]
) -> None:
    _dhcp_get_ip_by_arg_handler(httpserver, sample_ipaddress=sample_ipaddress)
    resp = dhcp._dhcp_get_ip_by_arg(sample_ipaddress["ipaddress"])
    assert resp == sample_ipaddress


@pytest.mark.parametrize("mac_in_use", [True, False])
@pytest.mark.parametrize("host_has_mac", [True, False])
@pytest.mark.parametrize("force", [True, False])
def test_assoc(
    httpserver: HTTPServer,
    sample_host: Dict[str, Any],
    mac_in_use: bool,
    host_has_mac: bool,
    force: bool,
) -> None:

    mac = sample_host["ipaddresses"][0]["macaddress"]
    ip_info = sample_host["ipaddresses"]

    if not mac_in_use:
        results = None
    else:
        results = ip_info

    if not host_has_mac:
        ip_info[0]["macaddress"] = None

    _dhcp_get_ip_by_arg_handler(httpserver, sample_host=sample_host)
    assoc_mac_to_ip_handler(httpserver, mac=mac, ip=ip_info[0], results=results)
    args = Namespace(name=sample_host["name"], mac=mac, force=force)

    ctx = nullcontext()
    msg = ""
    if mac_in_use and not force:
        ctx = pytest.raises(CliWarning)
        msg = "already in use"
    elif host_has_mac and not force:
        ctx = pytest.raises(CliWarning)
        msg = "has existing mac"

    with ctx as exc_info:
        dhcp.assoc(args)

    if exc_info is not None and msg:
        assert msg in exc_info.exconly().lower()


def test_disassoc(httpserver: HTTPServer, sample_host: Dict[str, Any]) -> None:
    _host_info_by_name_handler(httpserver, sample_host)

    ip = sample_host["ipaddresses"][0]
    httpserver.expect_oneshot_request(
        f"/api/v1/ipaddresses/{ip['id']}",
        method="PATCH",
        data=urllib.parse.urlencode({"macaddress": ""}),
    ).respond_with_data()

    args = Namespace(name=sample_host["name"])
    dhcp.disassoc(args)