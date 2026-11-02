"""JSON-lines debug log ``sbom-out/.state/sbom.log`` (contract sections 3.3 and 6.1).

The logger never raises. It never creates directories and never writes through a symlink or into a hard-linked file. Callers must not pass
secrets (NVD_API_KEY, header values, prompt text, URL userinfo) as fields.
"""
from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path
from typing import Any, Optional

MAX_TRACEBACK = 6000


class Logger:
    def __init__(self, path: Optional[Path], run_id: Optional[str] = None) -> None:
        self.path = Path(path) if path is not None else None
        self.run_id = run_id

    def _write(self, level: str, event: str, fields: Any) -> None:
        if self.path is None:
            return
        try:
            record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "event": event,
                      "run_id": self.run_id}
            for key, value in fields.items():
                if key not in record:
                    record[key] = value
            line = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
            data = line.encode("utf-8", "backslashreplace")
            target = str(self.path)
            if os.path.islink(target) or not os.path.isdir(os.path.dirname(target)):
                return
            from sbomlib import fsio                # function-local: context imports this module, fsio imports context
            fd = fsio.open_append(target)           # refuses symlinks, non-regular files and hard-linked files
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        except Exception:
            return

    def debug(self, event: str, **fields: Any) -> None:
        self._write("debug", event, fields)

    def info(self, event: str, **fields: Any) -> None:
        self._write("info", event, fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._write("warning", event, fields)

    def error(self, event: str, **fields: Any) -> None:
        self._write("error", event, fields)

    def exception(self, event: str, **fields: Any) -> None:
        """Error-level record carrying the traceback of the exception being handled."""
        try:
            text = traceback.format_exc()
        except Exception:
            text = ""
        fields = dict(fields)
        fields["traceback"] = text[-MAX_TRACEBACK:]
        self._write("error", event, fields)


class NullLogger(Logger):
    """Used before ``sbom-out/.state`` exists."""

    def __init__(self) -> None:
        super().__init__(None, None)
