from typing import Any, Dict, Optional

import pytest
from mreg_cli import dhcp
from mreg_cli.exceptions import CliWarning
from mreg_cli.util import format_mac
from pytest_httpserver import HTTPServer

from .handlers import assoc_mac_to_ip_handler
from .utils import macaddresses


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
