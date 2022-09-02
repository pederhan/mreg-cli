from typing import Any, Dict, Iterator
from mreg_cli import util
import pytest
from pytest_httpserver import HTTPServer


@pytest.fixture
def httpserver_original(httpserver: HTTPServer) -> Iterator[HTTPServer]:
    # A copy of the original httpserver, since we shadow the original
    # with our own version.
    yield httpserver


@pytest.fixture
def httpserver(httpserver: HTTPServer) -> Iterator[HTTPServer]:
    """Shadows the pytest_httpserver.httpserver fixture with our own that
    assigns the result of httpserver.url_for('') to util.mregurl."""
    util.mregurl = httpserver.url_for("")
    yield httpserver  # yield so that the httpserver is closed after the test


@pytest.fixture
def sample_network() -> Dict[str, Any]:
    return {
        "id": 66,
        "excluded_ranges": [
            {
                "id": 21,
                "created_at": "2020-12-03T17:04:23.876818+01:00",
                "updated_at": "2020-12-03T17:04:23.876855+01:00",
                "start_ip": "10.0.1.20",
                "end_ip": "10.0.1.30",
                "network": 66,
            }
        ],
        "created_at": "2020-12-03T17:04:23.200211+01:00",
        "updated_at": "2020-12-03T17:04:23.361019+01:00",
        "network": "10.0.1.0/24",
        "description": "Frozzzen",
        "vlan": None,
        "dns_delegated": False,
        "category": "",
        "location": "",
        "frozen": True,
        "reserved": 3,
    }


@pytest.fixture
def sample_network_ipv6() -> Dict[str, Any]:
    return {
        "id": 66,
        "excluded_ranges": [
            {
                "id": 21,
                "created_at": "2020-12-03T17:04:23.876818+01:00",
                "updated_at": "2020-12-03T17:04:23.876855+01:00",
                "start_ip": "7593:4588:f58f:f153:0000:0000:0000:1234",
                "end_ip": "7593:4588:f58f:f153:0000:0000:0000:4321",
                "network": 66,
            }
        ],
        "created_at": "2020-12-03T17:04:23.200211+01:00",
        "updated_at": "2020-12-03T17:04:23.361019+01:00",
        "network": "7593:4588:f58f:f153:0000:0000:0000:0000/64",
        "description": "Frozzzen",
        "vlan": None,
        "dns_delegated": False,
        "category": "",
        "location": "",
        "frozen": True,
        "reserved": 3,
    }


@pytest.fixture
def sample_zone() -> Dict[str, Any]:
    return {
        "zone": {
            "id": 10,
            "nameservers": [
                {
                    "id": 20,
                    "created_at": "2020-12-03T17:04:19.072289+01:00",
                    "updated_at": "2020-12-03T17:04:19.072326+01:00",
                    "name": "ns2.example.org",
                    "ttl": None,
                }
            ],
            "created_at": "2020-12-03T17:04:18.421880+01:00",
            "updated_at": "2020-12-03T17:04:25.952258+01:00",
            "updated": True,
            "primary_ns": "ns2.example.org",
            "email": "hostperson@example.org",
            "serialno": 12345,
            "serialno_updated_at": "2020-12-03T17:04:19.238809+01:00",
            "refresh": 360,
            "retry": 1800,
            "expire": 2400,
            "soa_ttl": 1800,
            "default_ttl": 300,
            "name": "example.org",
        }
    }


@pytest.fixture
def sample_ipaddress() -> Dict[str, Any]:
    return {
        "id": 113,
        "macaddress": "28:85:B1:60:54:DC",
        "created_at": "2020-12-03T17:04:42.990808+01:00",
        "updated_at": "2020-12-03T17:04:42.990836+01:00",
        "ipaddress": "10.0.0.5",
        "host": 172,
    }


@pytest.fixture
def sample_ipaddress_ipv6() -> Dict[str, Any]:
    return {
        "id": 113,
        "macaddress": "28:85:B1:60:54:DC",
        "created_at": "2020-12-03T17:04:42.990808+01:00",
        "updated_at": "2020-12-03T17:04:42.990836+01:00",
        "ipaddress": "7593:4588:f58f:f153:DEAD:BEEF:1234:1234",
        "host": 172,
    }


@pytest.fixture
def sample_txt() -> Dict[str, Any]:
    return {
        "id": 182,
        "created_at": "2020-12-03T17:04:42.577372+01:00",
        "updated_at": "2020-12-03T17:04:42.577400+01:00",
        "txt": "v=spf1 -all",
        "host": 172,
    }


@pytest.fixture
def sample_ptr_override() -> Dict[str, Any]:
    return {
        "id": 11,
        "created_at": "2020-12-03T17:04:56.898974+01:00",
        "updated_at": "2020-12-03T17:04:56.899005+01:00",
        "ipaddress": "10.0.0.20",
        "host": 172,
    }


@pytest.fixture
def sample_cname() -> Dict[str, Any]:
    return {
        "id": 11,
        "created_at": "2020-12-03T17:04:54.156765+01:00",
        "updated_at": "2020-12-03T17:04:54.156793+01:00",
        "name": "bar.example.com",
        "ttl": None,
        "zone": 10,
        "host": 173,
    }


@pytest.fixture
def sample_hinfo() -> Dict[str, Any]:
    return {
        "host": 172,
        "created_at": "2020-12-03T17:04:54.598153+01:00",
        "updated_at": "2020-12-03T17:04:54.598180+01:00",
        "cpu": "x86",
        "os": "Win",
    }


@pytest.fixture
def sample_loc() -> Dict[str, Any]:
    return {
        "host": 172,
        "created_at": "2020-12-03T17:04:55.056897+01:00",
        "updated_at": "2020-12-03T17:04:55.056927+01:00",
        "loc": "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    }


@pytest.fixture
def sample_mx() -> Dict[str, Any]:
    return {
        "id": 11,
        "created_at": "2020-12-03T17:04:55.492630+01:00",
        "updated_at": "2020-12-03T17:04:55.492659+01:00",
        "priority": 10,
        "mx": "mail.example.org",
        "host": 172,
    }


@pytest.fixture
def sample_host(
    sample_ipaddress: Dict[str, Any],
    sample_ptr_override: Dict[str, Any],
    sample_txt: Dict[str, Any],
    sample_cname: Dict[str, Any],
    sample_hinfo: Dict[str, Any],
    sample_loc: Dict[str, Any],
    sample_mx: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "id": 172,
        "ipaddresses": [sample_ipaddress],
        "cnames": [sample_cname],
        "mxs": [sample_mx],
        "txts": [sample_txt],
        "ptr_overrides": [sample_ptr_override],
        "hinfo": sample_hinfo,
        "loc": sample_loc,
        "created_at": "2020-12-03T17:04:42.566792+01:00",
        "updated_at": "2020-12-03T17:04:42.566820+01:00",
        "name": "foo.example.com",
        "contact": "",
        "ttl": None,
        "comment": "",
        "zone": 10,
    }


@pytest.fixture
def sample_naptr() -> Dict[str, Any]:
    return {
        "id": 11,
        "created_at": "2020-12-03T17:04:56.063025+01:00",
        "updated_at": "2020-12-03T17:04:56.063055+01:00",
        "preference": 16384,
        "order": 3,
        "flag": "u",
        "service": "sip",
        "regex": "[abc]+",
        "replacement": "wonk",
        "host": 172,
    }


@pytest.fixture
def sample_srv() -> Dict[str, Any]:
    return {
        "id": 11,
        "created_at": "2020-12-03T17:04:58.475354+01:00",
        "updated_at": "2020-12-03T17:04:58.475385+01:00",
        "name": "_sip._tcp.example.org",
        "priority": 10,
        "weight": 5,
        "port": 3456,
        "ttl": None,
        "zone": 10,
        "host": 172,
    }
