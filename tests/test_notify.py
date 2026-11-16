# SPDX-License-Identifier: GPL-3.0-or-later
import io
import json

from changepassword.notify import LIMIT, Discord


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_no_file_no_channel(tmp_path):
    asked = []
    for path in ('', str(tmp_path / 'none'), str(tmp_path / 'empty'), str(tmp_path / 'odd')):
        (tmp_path / 'empty').write_text('\n')
        (tmp_path / 'odd').write_text('http://not-https.example/hook\n')
        d = Discord(path, opener=lambda request, timeout: asked.append(request))
        assert d.webhook() is None and d.send('x') is False
    assert asked == []


def test_what_discord_is_sent(tmp_path):
    hook = tmp_path / 'hook'
    hook.write_text('https://discord.example/api/webhooks/1/abc\n')
    asked = []

    def opener(request, timeout):
        asked.append(request)
        return Answer(b'')

    assert Discord(str(hook), opener=opener).send('**a** changed @everyone ' + 'x' * 3000) is True
    request, = asked
    assert request.full_url == 'https://discord.example/api/webhooks/1/abc'
    body = json.loads(request.data)
    # nobody is pinged by a name in a message, and the message fits
    assert body['allowed_mentions'] == {'parse': []} and len(body['content']) == LIMIT
    # a new webhook in the file is used at once
    hook.write_text('https://discord.example/api/webhooks/2/def\n')
    Discord(str(hook), opener=opener).send('x')
    assert asked[-1].full_url.endswith('/2/def')


def test_a_discord_that_is_away_raises_nothing(tmp_path):
    hook = tmp_path / 'hook'
    hook.write_text('https://discord.example/api/webhooks/1/abc\n')

    def away(request, timeout):
        raise OSError('no route')

    assert Discord(str(hook), opener=away).send('x') is False
