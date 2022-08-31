from typing import Optional
import pytest
from pathlib import Path
from mreg_cli import log


@pytest.mark.parametrize("logfile", [None, "test.log"])
def test__write_log(tmp_path: Path, logfile: Optional[str]) -> None:
    # Test that no logfile has no effect
    if logfile is None:
        log.logfile = None
        log._write_log("line 1")
        # Nothing happens
        assert log.logfile is None
        return

    f = tmp_path / logfile
    assert not f.exists()  # File doesn't exist yet
    log.logfile = str(f)

    # Test that first write creates the file (a+ should create the file)
    log._write_log("line 1")
    assert f.read_text() == "line 1\n"

    # Test that subsequent writes append to the file
    log._write_log("line 2")
    assert f.read_text() == "line 1\nline 2\n"
    log._write_log("line 3")
    assert f.read_text() == "line 1\nline 2\nline 3\n"
