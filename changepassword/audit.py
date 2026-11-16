# SPDX-License-Identifier: GPL-3.0-or-later
"""The log of who changed whose password.

One line of JSON per attempt, added at the end of a file and never
rewritten: when (UTC), who (changer), whose (target), from which
address, how it went (outcome, detail) and the id of the one-time link
that was made. Never the password, never the link's key - the id alone
opens nothing.
"""
from __future__ import annotations

import datetime
import json
import os

FIELDS = ('at', 'changer', 'target', 'address', 'outcome', 'detail', 'link')


class Audit:
    def __init__(self, path: str):
        self.path = path

    def check(self) -> None:
        """Raises OSError when the log cannot be written."""
        with open(self.path, 'a', encoding='utf-8'):
            pass

    def record(self, **entry) -> None:
        entry['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        line = json.dumps({name: str(entry.get(name) or '') for name in FIELDS},
                          ensure_ascii=True)
        # one write of one line: lines of two workers do not mix
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, (line + '\n').encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def latest(self, count: int) -> list[dict]:
        """The newest COUNT entries, newest first."""
        try:
            with open(self.path, encoding='utf-8') as handle:
                lines = handle.readlines()[-count:]
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out
