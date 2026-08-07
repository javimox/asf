"""Small atomic filesystem write helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text_atomic(path: Path, payload: str) -> None:
    """Replace *path* atomically with UTF-8 text.

    The temporary file is created beside the destination so ``os.replace``
    remains atomic on the destination filesystem. Any uncommitted temporary
    file is removed if writing or replacement fails.
    """

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
