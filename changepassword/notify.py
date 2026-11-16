# SPDX-License-Identifier: GPL-3.0-or-later
"""Tell a Discord channel what happened.

The channel's webhook address is a secret - whoever has it can post in
the channel - so it is not a setting: it is read from a file, every
time something is sent (a new webhook needs no restart). No file, or an
empty one, means the channel is off.

Telling is an extra. The log file is the record; a Discord that does
not answer never stops or fails a change. send() says whether the
message went out and raises nothing.
"""
from __future__ import annotations

import json
import urllib.request

LIMIT = 1900        # Discord takes 2000 characters


class Discord:
    def __init__(self, path: str, timeout: int = 10, opener=None):
        self.path, self.timeout = path, timeout
        self.opener = opener or urllib.request.urlopen

    def webhook(self) -> str | None:
        if not self.path:
            return None
        try:
            with open(self.path, encoding='utf-8') as handle:
                url = handle.read().strip()
        except OSError:
            return None
        return url if url.startswith('https://') else None

    def send(self, text: str) -> bool:
        url = self.webhook()
        if url is None:
            return False
        body = json.dumps({'content': text[:LIMIT],
                           # a name in a message never pings anybody
                           'allowed_mentions': {'parse': []}}).encode()
        request = urllib.request.Request(url, data=body, method='POST', headers={
            'Content-Type': 'application/json', 'User-Agent': 'changepassword'})
        try:
            with self.opener(request, timeout=self.timeout):
                return True
        except Exception:       # telling is an extra: nothing it does may fail a change
            return False
