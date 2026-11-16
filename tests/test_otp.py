# SPDX-License-Identifier: GPL-3.0-or-later
"""The one-time link: what is sent to the link service, and that the
key in the link opens it. The encryption is the real gpg's."""
import io
import json
import shutil
import subprocess
import urllib.error

import pytest

from changepassword.otp import KEY_LENGTH, Otp, OtpError, encrypt, new_key

needs_gpg = pytest.mark.skipif(shutil.which('gpg') is None, reason='no gpg here')


def gpg(tmp_path, *args, **kw):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700, exist_ok=True)
    return subprocess.run(['gpg', '--batch', '--no-options', '--homedir', str(home),
                           '--pinentry-mode', 'loopback'] + list(args),
                          capture_output=True, **kw)


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_a_key_like_yopass_makes_them():
    keys = {new_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(len(k) == KEY_LENGTH and k.replace('-', '').replace('_', '').isalnum()
               for k in keys)


@needs_gpg
def test_the_key_opens_the_message_and_another_does_not(tmp_path):
    message = encrypt('S3cretS3cret', 'the-key-0123456789abcd')
    assert message.startswith('-----BEGIN PGP MESSAGE-----')
    assert 'S3cretS3cret' not in message
    got = gpg(tmp_path, '--passphrase', 'the-key-0123456789abcd', '--decrypt',
              input=message.encode())
    assert got.returncode == 0 and got.stdout == b'S3cretS3cret'
    assert gpg(tmp_path, '--passphrase', 'another-key', '--decrypt',
               input=message.encode()).returncode != 0


@needs_gpg
def test_the_message_is_what_yopass_writes(tmp_path):
    # a passphrase-only message: AES-256, the key stretched with salted
    # and iterated SHA-256, integrity protected, not compressed
    message = encrypt('S3cretS3cret', 'the-key-0123456789abcd')
    packets = gpg(tmp_path, '--passphrase', 'the-key-0123456789abcd', '--list-packets',
                  input=message.encode()).stdout.decode()
    assert ':symkey enc packet: version 4, cipher 9, aead 0, s2k 3, hash 8' in packets
    assert 'mdc_method: 2' in packets
    assert ':compressed packet' not in packets and ':pubkey enc packet' not in packets


@needs_gpg
def test_what_the_link_service_is_sent_and_the_link(tmp_path):
    asked = []

    def opener(request, timeout):
        asked.append(request)
        return Answer(json.dumps({'message': '0f3c9a2e-1111-4222-8333-444455556666'}).encode())

    link, secret_id = Otp('https://otp.example:8443/', 'https://otp.example/', 86400,
                          opener=opener).store('S3cretS3cret')
    request, = asked
    assert request.full_url == 'https://otp.example:8443/create/secret'
    assert request.get_method() == 'POST'
    body = json.loads(request.data)
    assert body['expiration'] == 86400 and body['one_time'] is True
    assert 'S3cretS3cret' not in request.data.decode()
    assert secret_id == '0f3c9a2e-1111-4222-8333-444455556666'
    start = 'https://otp.example/#/s/%s/' % secret_id
    assert link.startswith(start)
    key = link[len(start):]
    assert len(key) == KEY_LENGTH
    # the key in the link opens what was sent - and was not sent itself
    assert key not in request.data.decode()
    got = gpg(tmp_path, '--passphrase', key, '--decrypt', input=body['message'].encode())
    assert got.stdout == b'S3cretS3cret'


@needs_gpg
def test_a_link_service_that_is_away_or_odd():
    def refused(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, 'Forbidden', {}, None)

    def away(request, timeout):
        raise OSError('no route')

    def odd(request, timeout):
        return Answer(b'{"message": {"not": "an id"}}')

    for opener in (refused, away, odd):
        with pytest.raises(OtpError):
            Otp('https://otp.example:8443', 'https://otp.example', opener=opener).store('x')


def test_without_gpg_it_says_so():
    with pytest.raises(OtpError):
        encrypt('x', 'key', gpg='/nonexistent/gpg')
