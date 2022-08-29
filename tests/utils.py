from typing import Iterable, Optional, overload
from typing_extensions import Literal


@overload
def macaddresses(with_none: Literal[True]) -> Iterable[Optional[str]]:
    ...


@overload
def macaddresses(with_none: Literal[False]) -> Iterable[Optional[str]]:
    ...


@overload
def macaddresses() -> Iterable[str]:
    ...


def macaddresses(with_none: bool = False) -> Iterable[Optional[str]]:
    """Generator that yields valid MAC addresses in all 4 valid formats.
    If `with_none` is True, yields None as well.
    """
    for mac in [
        "28-85-B1-60-54-DC",  # Dash-separated
        "28:85:B1:60:54:DC",  # Colon-separated
        "28.85.B1.60.54.DC",  # Dot-separated
        "2885B16054DC",  # No separators
    ]:
        yield mac
    if with_none:
        yield None