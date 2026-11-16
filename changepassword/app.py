# SPDX-License-Identifier: GPL-3.0-or-later
"""The web application.

  /                 whose password? (a form)
  /find    (POST)   the person that was found, and "change it?"
  /change  (POST)   change it: a new random password goes into the
                    directory and into a one-time link, and the link is
                    shown - once
  /log              who changed whose password, and when
  /healthz          for a monitor

WHO IS ASKING. changepassword does not log anybody in and does not
decide who is allowed. A reverse proxy in front does both (the
directory login, and the group that may change passwords) and hands
over the name in a header (X-Remote-User) and the visitor's address in
another (X-Real-IP). changepassword listens on the loopback address
only and believes those headers - and refuses every page without a
name. /healthz is the one exception: it tells nothing but "ok".

WHAT A CHANGE IS. The new password is made here (random letters and
digits), never typed and never shown: it is put into the one-time link
service first, then into the directory, and what the changer gets is
the link. Nothing is changed unless both worked, in that order - a
link whose password never reached the directory is useless and dies by
itself.

THE TICKET. /change takes nothing but a signed ticket that /find made
for THIS changer and THAT person a few minutes ago. A page somewhere
else cannot make a logged-in changer's browser change a password.

THE LOG. Every attempt - changed or failed - is written down before
the changer sees the result: who, whose, when, from where. Never the
password, never the link's key. The same is told to a Discord channel
when one is configured; that is an extra, and a Discord that does not
answer stops nothing.
"""
from __future__ import annotations

import datetime
import os
import re
import secrets as random_source
import string
import zoneinfo

from flask import Flask, abort, render_template, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import __version__
from .audit import Audit
from .directory import DirectoryError
from .otp import OtpError

TICKET_AGE = 5 * 60         # seconds between "found" and "change it"
ALPHABET = string.ascii_letters + string.digits
_USERNAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
_OPEN = ('healthz', 'static')      # endpoints without a login
LIFE_WORDS = {3600: '1 hour', 86400: '1 day', 604800: '1 week'}


def new_password(length: int) -> str:
    return ''.join(random_source.choice(ALPHABET) for _ in range(length))


def create_app(directory=None, otp=None, audit=None, config: dict | None = None,
               notify=None) -> Flask:
    """The application. DIRECTORY, OTP, AUDIT and NOTIFY are anything
    with the methods of directory.Directory, otp.Otp, audit.Audit and
    notify.Discord (the tests hand in their own); by default they are
    made from the environment."""
    app = Flask(__name__)
    env = os.environ.get
    app.config.update(
        LDAP_URIS=env('CHANGEPASSWORD_LDAP_URIS', ''),
        LDAP_BASE=env('CHANGEPASSWORD_LDAP_BASE', ''),
        LDAP_CERT=env('CHANGEPASSWORD_LDAP_CERT', ''),
        LDAP_KEY=env('CHANGEPASSWORD_LDAP_KEY', ''),
        LDAP_CA=env('CHANGEPASSWORD_LDAP_CA', ''),
        OTP_API=env('CHANGEPASSWORD_OTP_API', ''),
        OTP_URL=env('CHANGEPASSWORD_OTP_URL', ''),
        LINK_LIFE=int(env('CHANGEPASSWORD_LINK_LIFE', '86400')),
        LENGTH=int(env('CHANGEPASSWORD_LENGTH', '40')),
        AUDIT=env('CHANGEPASSWORD_AUDIT', ''),
        # a file holding the Discord webhook to tell (none: nobody is told)
        DISCORD_FILE=env('CHANGEPASSWORD_DISCORD_FILE', ''),
        KEY_FILE=env('CHANGEPASSWORD_KEY_FILE', ''),
        TIMEZONE=env('CHANGEPASSWORD_TIMEZONE', 'UTC'),
        TITLE=env('CHANGEPASSWORD_TITLE', 'changepassword'),
        USER_HEADER=env('CHANGEPASSWORD_USER_HEADER', 'X-Remote-User'),
        ADDRESS_HEADER=env('CHANGEPASSWORD_ADDRESS_HEADER', 'X-Real-IP'),
    )
    app.config.update(config or {})
    if app.config['LINK_LIFE'] not in LIFE_WORDS:
        raise RuntimeError('CHANGEPASSWORD_LINK_LIFE is %r: the link service knows %s seconds'
                           % (app.config['LINK_LIFE'], ', '.join(map(str, sorted(LIFE_WORDS)))))
    if app.config['LENGTH'] < 20:
        raise RuntimeError('CHANGEPASSWORD_LENGTH is %d: at least 20' % app.config['LENGTH'])

    if directory is None:
        from .directory import Directory
        for name in ('LDAP_URIS', 'LDAP_BASE', 'LDAP_CERT', 'LDAP_KEY', 'LDAP_CA'):
            if not app.config[name]:
                raise RuntimeError('CHANGEPASSWORD_%s is not set: no directory to write to' % name)
        directory = Directory(app.config['LDAP_URIS'].split(), app.config['LDAP_BASE'],
                              app.config['LDAP_CERT'], app.config['LDAP_KEY'],
                              app.config['LDAP_CA'])
    if otp is None:
        from .otp import Otp
        if not app.config['OTP_API'] or not app.config['OTP_URL']:
            raise RuntimeError('CHANGEPASSWORD_OTP_API / _OTP_URL are not set: nowhere to put '
                               'the new password')
        otp = Otp(app.config['OTP_API'], app.config['OTP_URL'], app.config['LINK_LIFE'])
    if audit is None:
        if not app.config['AUDIT']:
            raise RuntimeError('CHANGEPASSWORD_AUDIT is not set: no log to write the changes to')
        audit = Audit(app.config['AUDIT'])
    if notify is None:
        from .notify import Discord
        notify = Discord(app.config['DISCORD_FILE'])

    tickets = URLSafeTimedSerializer(_key(app), salt='changepassword-ticket')
    tz = zoneinfo.ZoneInfo(app.config['TIMEZONE'])
    life = LIFE_WORDS[app.config['LINK_LIFE']]

    # --- who is asking ---------------------------------------------------

    def username() -> str | None:
        name = request.headers.get(app.config['USER_HEADER'], '').strip()
        return name if _USERNAME.match(name) else None

    def address() -> str:
        return request.headers.get(app.config['ADDRESS_HEADER'], '').strip() \
            or request.remote_addr or ''

    @app.before_request
    def named_visitors_only():
        if request.endpoint in _OPEN or request.endpoint is None:
            return None
        if username() is None:
            abort(401)
        return None

    @app.template_filter('when')
    def when(value):
        if not value:
            return ''
        if isinstance(value, str):
            value = datetime.datetime.fromisoformat(value)
        return value.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')

    @app.context_processor
    def common():
        return {'title': app.config['TITLE'], 'version': __version__,
                'timezone': app.config['TIMEZONE'], 'user': username(), 'life': life,
                'length': app.config['LENGTH']}

    @app.after_request
    def headers(response):
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Cache-Control', 'no-store')
        return response

    def note(target: str, outcome: str, detail: str = '', link: str = '') -> None:
        """Into the log and the server's journal, and to Discord."""
        audit.record(changer=username(), target=target, address=address(),
                     outcome=outcome, detail=detail, link=link)
        app.logger.warning('%s: the password of %s, by %s from %s%s', outcome, target,
                           username(), address(), ' (%s)' % detail if detail else '')
        if outcome == 'changed':
            words = '**%s** changed the password of **%s** (from %s)' % (
                username(), target, address())
        else:
            words = 'FAILED: **%s** tried to change the password of **%s** (from %s): %s' % (
                username(), target, address(), detail)
        if not notify.send(words) and notify.webhook() is not None:
            app.logger.error('Discord was not told (%s: %s)', outcome, target)

    # --- the pages --------------------------------------------------------

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.post('/find')
    def find():
        asked = request.form.get('uid', '').strip()
        if not _USERNAME.match(asked):
            return render_template('index.html', asked=asked,
                                   problem='That is not a username.'), 400
        try:
            person = directory.find(asked)
        except DirectoryError as exc:
            app.logger.error('looking up %s failed: %s', asked, exc)
            return render_template('index.html', asked=asked,
                                   problem='The directory could not be asked. Try again.'), 502
        if person is None:
            return render_template('index.html', asked=asked,
                                   problem='The directory has nobody called %s.' % asked), 404
        ticket = tickets.dumps({'u': username(), 't': person['uid'], 'd': person['dn']})
        return render_template('confirm.html', person=person, ticket=ticket,
                               minutes=TICKET_AGE // 60)

    @app.post('/change')
    def change():
        user = username()
        try:
            ticket = tickets.loads(request.form.get('ticket', ''), max_age=TICKET_AGE)
        except BadSignature:        # also: too old
            abort(403, 'Find the person again: that question is too old, or not yours.')
        if ticket.get('u') != user:
            abort(403, 'Find the person again: that question is not yours.')
        target, dn = ticket['t'], ticket['d']
        try:
            # nothing is changed that cannot be written down
            audit.check()
        except OSError as exc:
            app.logger.error('the log cannot be written: %s', exc)
            abort(500, 'The log cannot be written, so nothing was changed.')
        try:
            person = directory.find(target)
        except DirectoryError as exc:
            note(target, 'failed', 'the directory could not be asked')
            app.logger.error('looking up %s failed: %s', target, exc)
            abort(502, 'The directory could not be asked. Nothing was changed.')
        if person is None or person['dn'] != dn:
            note(target, 'failed', 'the person is not there any more')
            abort(409, 'The directory no longer has %s as it was found. Nothing was changed.'
                  % target)
        password = new_password(app.config['LENGTH'])
        try:
            link, link_id = otp.store(password)
        except OtpError as exc:
            note(target, 'failed', 'the link service did not take the password')
            app.logger.error('the link service: %s', exc)
            abort(502, 'The link service did not take the new password. Nothing was changed.')
        try:
            directory.set_password(dn, password)
        except DirectoryError as exc:
            note(target, 'failed', 'the directory did not take the password', link_id)
            app.logger.error('setting the password of %s failed: %s', target, exc)
            abort(502, 'The directory did not take the new password. Nothing was changed; '
                       'the link that was made is of no use.')
        note(target, 'changed', link=link_id)
        return render_template('done.html', person=person, link=link)

    @app.get('/log')
    def log():
        return render_template('log.html', entries=audit.latest(200))

    @app.get('/healthz')
    def healthz():
        return 'ok\n', 200, {'Content-Type': 'text/plain; charset=utf-8'}

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(409)
    @app.errorhandler(500)
    @app.errorhandler(502)
    def problem(error):
        code = getattr(error, 'code', 500) or 500
        message = getattr(error, 'description', None) or 'Something went wrong.'
        if code == 401:
            message = 'Nobody is logged in.'
            return message + '\n', 401, {'Content-Type': 'text/plain; charset=utf-8'}
        return render_template('error.html', message=message), code

    return app


def _key(app: Flask) -> bytes:
    """What the tickets are signed with. Every worker process must have
    the same: a file (made once, readable by changepassword only).
    Without one a key is made up for this process - fine for one
    process."""
    path = app.config.get('KEY_FILE')
    if path:
        with open(path, 'rb') as handle:
            key = handle.read().strip()
        if len(key) < 32:
            raise RuntimeError('%s holds less than 32 bytes: not a key' % path)
        return key
    app.logger.warning('CHANGEPASSWORD_KEY_FILE is not set: tickets are signed with a key '
                       'of this process only')
    return random_source.token_bytes(32)
