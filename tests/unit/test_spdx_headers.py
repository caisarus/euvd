"""X.3 hygiene (plans/test_plan.md): every shipped source file declares the license.

The project is EUPL-1.2; a source file without the SPDX tag is ambiguous the moment it is
copied out of the repository. Only `src/**` is checked — tests and scripts ship nowhere.
"""

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src"


def test_every_source_file_declares_eupl() -> None:
    missing = [
        str(path)
        for path in sorted(SRC.rglob("*.py"))
        if "SPDX-License-Identifier: EUPL-1.2" not in path.read_text(encoding="utf-8")[:200]
    ]
    assert not missing, f"source files without an SPDX header: {missing}"
