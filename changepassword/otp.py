# SPDX-License-Identifier: GPL-3.0-or-later
"""Put a secret into the one-time link service (Yopass) and get its link.

As Yopass's own page and command line do it: the secret is encrypted
HERE with a key made here (an OpenPGP message, a passphrase as the
key), the service is given the ciphertext only, and the key lives in
the link's fragment - which a browser never sends to a server. The
service cannot read what it keeps.

The encryption is GnuPG's (`gpg --symmetric`): AES-256, the key
stretched with salted and iterated SHA-256, no compression - what
Yopass itself writes.
"""
from __future__ import annotations

import base64
import json
import os
import secrets as random_source
import subprocess
import tempfile
import urllib.error
import urllib.request

KEY_LENGTH = 22         # Yopass's own


class OtpError(Exception):
    pass


def new_key() -> str:
    return base64.urlsafe_b64encode(random_source.token_bytes(KEY_LENGTH)).decode()[:KEY_LENGTH]


def encrypt(secret: str, key: str, gpg: str = 'gpg') -> str:
    """SECRET as an armoured OpenPGP message that KEY opens."""
    with tempfile.TemporaryDirectory(prefix='changepassword-gpg-') as home:
        read, write = os.pipe()
        try:
            os.write(write, key.encode())
            os.close(write)
            write = None
            done = subprocess.run(
                [gpg, '--batch', '--no-options', '--quiet', '--homedir', home,
                 '--pinentry-mode', 'loopback', '--passphrase-fd', str(read),
                 '--symmetric', '--armor', '--cipher-algo', 'AES256',
                 '--s2k-digest-algo', 'SHA256', '--compress-algo', 'none'],
                input=secret.encode(), capture_output=True, pass_fds=(read,), timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OtpError('gpg: %s' % type(exc).__name__)
        finally:
            os.close(read)
            if write is not None:
                os.close(write)
            # the agent gpg started for this directory
            subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'],
                           capture_output=True, check=False)
    message = done.stdout.decode('ascii', 'replace')
    if done.returncode != 0 or 'BEGIN PGP MESSAGE' not in message:
        raise OtpError('gpg did not encrypt (exit %d)' % done.returncode)
    return message


class Otp:
    def __init__(self, api: str, url: str, life: int = 86400, timeout: int = 15,
                 opener=None):
        """API is where secrets are created, URL the address people
        open links at; LIFE the seconds an unopened link lives."""
        self.api, self.url = api.rstrip('/'), url.rstrip('/')
        self.life, self.timeout = life, timeout
        self.opener = opener or urllib.request.urlopen

    def store(self, secret: str) -> tuple[str, str]:
        """(the link, the secret's id). The link opens once."""
        key = new_key()
        body = json.dumps({'message': encrypt(secret, key), 'expiration': self.life,
                           'one_time': True}).encode()
        request = urllib.request.Request(
            self.api + '/create/secret', data=body, method='POST',
            headers={'Content-Type': 'application/json'})
        try:
            with self.opener(request, timeout=self.timeout) as response:
                secret_id = json.loads(response.read())['message']
        except urllib.error.HTTPError as exc:
            raise OtpError('the link service answered HTTP %d' % exc.code)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise OtpError('the link service: %s' % type(exc).__name__)
        if not isinstance(secret_id, str) or not secret_id.replace('-', '').isalnum():
            raise OtpError('the link service gave no id')
        return '%s/#/s/%s/%s' % (self.url, secret_id, key), secret_id
