import sys
from typing import Iterable, Optional, overload
from typing_extensions import Literal

import pytest


@overload
def macaddresses(
    limit: Optional[int] = ..., with_none: Literal[True] = True
) -> Iterable[Optional[str]]:
    ...


@overload
def macaddresses(
    limit: Optional[int] = ..., with_none: Literal[False] = False
) -> Iterable[Optional[str]]:
    ...


def macaddresses(
    limit: Optional[int] = None, with_none: bool = False
) -> Iterable[Optional[str]]:
    """Generator that yields valid MAC addresses in all 4 valid formats.
    If `with_none` is True, yields None as well.
    """
    for i, mac in enumerate(
        [
            "28-85-B1-60-54-DC",  # Dash-separated
            "28:85:B1:60:54:DC",  # Colon-separated
            "28.85.B1.60.54.DC",  # Dot-separated
            "2885B16054DC",  # No separators
        ]
    ):
        if limit is not None and i >= limit:
            break
        yield mac
    if with_none:
        yield None


def is_py36() -> bool:
    """Return True if we are running on Python 3.6 or below"""
    return sys.version_info < (3, 7)


requires_nullcontext = pytest.mark.skipif(
    is_py36(), reason="contextlib.nullcontext is required to run the test"
)