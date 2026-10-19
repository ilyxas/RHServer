from __future__ import annotations

import pytest

from rh_agent.__main__ import main as rh_agent
from rh_cli.rhcore import main as rhcore
from rh_cli.rhpage import main as rhpage
from rh_common import __version__


@pytest.mark.parametrize(
    ("main", "prog"), [(rhcore, "rhcore"), (rhpage, "rhpage"), (rh_agent, "rh-agent")]
)
def test_version(main, prog, capsys) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"{prog} {__version__}"
