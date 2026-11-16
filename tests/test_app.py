# SPDX-License-Identifier: GPL-3.0-or-later
"""The pages, with stand-ins for the directory, the link service and
the log."""
import re

import pytest

pytest.importorskip('flask')

from changepassword.app import ALPHABET, create_app, length_range, new_password  # noqa: E402
from changepassword.audit import Audit  # noqa: E402
from changepassword.directory import DirectoryError  # noqa: E402
from changepassword.otp import OtpError  # noqa: E402

ME = {'X-Remote-User': 'alice', 'X-Real-IP': '192.0.2.13'}
BOB = {'dn': 'uid=bob,ou=people,dc=example,dc=org', 'uid': 'bob',
          'name': 'Bob Example'}


class Directory:
    def __init__(self):
        self.people = {'bob': dict(BOB)}
        self.set = []
        self.broken = self.refuses = False

    def find(self, uid):
        if self.broken:
            raise DirectoryError('away')
        return self.people.get(uid)

    def set_password(self, dn, password):
        if self.refuses:
            raise DirectoryError('no')
        self.set.append((dn, password))


class Otp:
    def __init__(self):
        self.stored = []
        self.broken = False

    def store(self, secret):
        if self.broken:
            raise OtpError('away')
        self.stored.append(secret)
        return 'https://otp.example/#/s/id-%d/THEKEY' % len(self.stored), 'id-%d' % len(self.stored)


class Notify:
    def __init__(self):
        self.said = []
        self.answers = True

    def webhook(self):
        return 'https://discord.example/hook'

    def send(self, text):
        self.said.append(text)
        return self.answers


@pytest.fixture
def world(tmp_path):
    class World:
        directory, otp, notify = Directory(), Otp(), Notify()
        audit = Audit(str(tmp_path / 'audit.log'))
    w = World()
    w.app = create_app(w.directory, w.otp, w.audit,
                       {'TESTING': True, 'TIMEZONE': 'Europe/Stockholm'}, notify=w.notify)
    w.client = w.app.test_client()
    return w


def ticket(world, uid='bob', headers=ME):
    page = world.client.post('/find', headers=headers, data={'uid': uid}).get_data(as_text=True)
    return re.search(r'name="ticket" value="([^"]+)"', page).group(1)


# --- nobody without a name --------------------------------------------------

def test_nothing_without_a_name(world):
    for path in ('/', '/log'):
        assert world.client.get(path).status_code == 401, path
        assert world.client.get(path, headers={'X-Remote-User': 'a b;c'}).status_code == 401
    for path in ('/find', '/change'):
        assert world.client.post(path, data={'uid': 'bob'}).status_code == 401
    assert world.directory.set == [] and world.otp.stored == []


def test_the_monitor_needs_no_name(world):
    got = world.client.get('/healthz')
    assert got.status_code == 200 and got.get_data(as_text=True) == 'ok\n'


# --- finding ----------------------------------------------------------------

def test_finding_shows_the_person_and_changes_nothing(world):
    got = world.client.post('/find', headers=ME, data={'uid': ' bob '})
    page = got.get_data(as_text=True)
    assert got.status_code == 200 and 'Bob Example' in page and 'name="ticket"' in page
    assert world.directory.set == [] and world.otp.stored == []
    assert world.audit.latest(10) == []


def test_nobody_by_that_name(world):
    got = world.client.post('/find', headers=ME, data={'uid': 'nosuch'})
    assert got.status_code == 404 and 'nobody called nosuch' in got.get_data(as_text=True)
    got = world.client.post('/find', headers=ME, data={'uid': 'a)(uid=*'})
    assert got.status_code == 400
    world.directory.broken = True
    assert world.client.post('/find', headers=ME, data={'uid': 'bob'}).status_code == 502


# --- changing ---------------------------------------------------------------

def test_a_change_end_to_end(world):
    got = world.client.post('/change', headers=ME, data={'ticket': ticket(world)})
    page = got.get_data(as_text=True)
    assert got.status_code == 200
    (dn, password), = world.directory.set
    assert dn == BOB['dn']
    # random letters and digits, 40 to 50 of them, the same in the link
    # service and the directory
    assert 40 <= len(password) <= 50 and set(password) <= set(ALPHABET)
    assert world.otp.stored == [password]
    # the changer gets the link - never the password
    assert 'https://otp.example/#/s/id-1/THEKEY' in page and password not in page
    assert got.headers['Cache-Control'] == 'no-store'
    # and it is in the log: who, whose, from where, the link's id - not its key
    entry, = world.audit.latest(10)
    assert (entry['changer'], entry['target'], entry['address'], entry['outcome'],
            entry['link']) == ('alice', 'bob', '192.0.2.13', 'changed', 'id-1')
    assert 'THEKEY' not in open(world.audit.path).read()
    assert password not in open(world.audit.path).read()


def test_two_changes_two_passwords(world):
    for _ in range(2):
        assert world.client.post('/change', headers=ME,
                                 data={'ticket': ticket(world)}).status_code == 200
    assert world.otp.stored[0] != world.otp.stored[1]


def test_only_a_ticket_changes_anything(world):
    for bad in ('', 'nonsense', ticket(world)[:-2]):
        assert world.client.post('/change', headers=ME, data={'ticket': bad}).status_code == 403
    # a ticket is the changer's own
    other = {'X-Remote-User': 'carol', 'X-Real-IP': '10.0.0.9'}
    assert world.client.post('/change', headers=other,
                             data={'ticket': ticket(world)}).status_code == 403
    # a username in the form is not looked at
    assert world.client.post('/change', headers=ME, data={'uid': 'bob'}).status_code == 403
    assert world.directory.set == [] and world.otp.stored == []


def test_an_old_ticket_is_refused(world, monkeypatch):
    t = ticket(world)
    import itsdangerous.timed
    real = itsdangerous.timed.time.time
    monkeypatch.setattr(itsdangerous.timed.time, 'time', lambda: real() + 6 * 60)
    assert world.client.post('/change', headers=ME, data={'ticket': t}).status_code == 403
    assert world.directory.set == []


def test_the_link_service_away_changes_nothing(world):
    t = ticket(world)
    world.otp.broken = True
    got = world.client.post('/change', headers=ME, data={'ticket': t})
    assert got.status_code == 502 and 'Nothing was changed' in got.get_data(as_text=True)
    assert world.directory.set == []
    entry, = world.audit.latest(10)
    assert entry['outcome'] == 'failed' and 'link service' in entry['detail']


def test_the_directory_refusing_is_said_and_logged(world):
    t = ticket(world)
    world.directory.refuses = True
    got = world.client.post('/change', headers=ME, data={'ticket': t})
    page = got.get_data(as_text=True)
    assert got.status_code == 502 and 'Nothing was changed' in page
    # the link that was made is not handed out
    assert 'otp.example' not in page
    entry, = world.audit.latest(10)
    assert entry['outcome'] == 'failed' and entry['link'] == 'id-1'


def test_the_person_gone_between_the_two_steps(world):
    t = ticket(world)
    world.directory.people['bob']['dn'] = 'uid=bob,ou=other,dc=example'
    assert world.client.post('/change', headers=ME, data={'ticket': t}).status_code == 409
    del world.directory.people['bob']
    assert world.client.post('/change', headers=ME, data={'ticket': t}).status_code == 409
    assert world.directory.set == [] and world.otp.stored == []


def test_no_log_no_change(world, tmp_path):
    t = ticket(world)
    world.audit.path = str(tmp_path / 'no' / 'such' / 'dir' / 'audit.log')
    got = world.client.post('/change', headers=ME, data={'ticket': t})
    assert got.status_code == 500 and 'nothing was changed' in got.get_data(as_text=True)
    assert world.directory.set == [] and world.otp.stored == []


# --- telling Discord --------------------------------------------------------

def test_discord_is_told_who_and_whose_and_nothing_secret(world):
    page = world.client.post('/change', headers=ME,
                             data={'ticket': ticket(world)}).get_data(as_text=True)
    said, = world.notify.said
    assert said == '**alice** changed the password of **bob** (from 192.0.2.13)'
    assert world.otp.stored[0] not in said and 'THEKEY' not in said and 'otp.example' not in said
    assert 'otp.example' in page
    world.directory.refuses = True
    world.client.post('/change', headers=ME, data={'ticket': ticket(world)})
    assert world.notify.said[-1].startswith(
        'FAILED: **alice** tried to change the password of **bob**')
    # looking somebody up tells nobody
    world.client.post('/find', headers=ME, data={'uid': 'bob'})
    assert len(world.notify.said) == 2


def test_discord_is_told_which_page_when_the_page_knows_its_address(world, tmp_path):
    app = create_app(world.directory, world.otp, Audit(str(tmp_path / 'c.log')),
                     {'TESTING': True, 'URL': 'https://changepassword.example'},
                     notify=world.notify)
    client = app.test_client()

    def change():
        page = client.post('/find', headers=ME, data={'uid': 'bob'}).get_data(as_text=True)
        return client.post('/change', headers=ME, data={
            'ticket': re.search(r'name="ticket" value="([^"]+)"', page).group(1)})
    change()
    assert world.notify.said[-1] == ('**alice** changed the password of **bob** '
                                     '(from 192.0.2.13) via <https://changepassword.example>')
    world.directory.refuses = True
    change()
    assert world.notify.said[-1] == (
        'FAILED: **alice** tried to change the password of **bob** (from 192.0.2.13) '
        'via <https://changepassword.example>: the directory did not take the password')
    with pytest.raises(RuntimeError, match='CHANGEPASSWORD_URL'):
        create_app(world.directory, world.otp, world.audit, {'URL': 'not an address'},
                   notify=world.notify)


def test_a_discord_that_does_not_answer_stops_nothing(world):
    world.notify.answers = False
    got = world.client.post('/change', headers=ME, data={'ticket': ticket(world)})
    assert got.status_code == 200 and len(world.directory.set) == 1
    assert world.audit.latest(10)[0]['outcome'] == 'changed'


# --- the log page -----------------------------------------------------------

def test_the_log_page(world):
    assert 'Nobody has changed a password here yet' in world.client.get(
        '/log', headers=ME).get_data(as_text=True)
    world.client.post('/change', headers=ME, data={'ticket': ticket(world)})
    world.otp.broken = True
    world.client.post('/change', headers=ME, data={'ticket': ticket(world)})
    page = world.client.get('/log', headers=ME).get_data(as_text=True)
    assert page.index('failed') < page.index('changed')         # newest first
    assert 'alice' in page and 'bob' in page and '192.0.2.13' in page


def test_the_settings_are_checked():
    with pytest.raises(RuntimeError, match='LINK_LIFE'):
        create_app(Directory(), Otp(), Audit('/dev/null'), {'LINK_LIFE': 1234})
    for bad, why in (('8', 'at least 20'), ('8-40', 'at least 20'), ('50-40', 'shortest first'),
                     ('40-500', 'at most 128'), ('forty', 'a range like'), ('40-', None)):
        if why is None:
            assert length_range(bad) == (40, 40)
            continue
        with pytest.raises(RuntimeError, match=why):
            create_app(Directory(), Otp(), Audit('/dev/null'), {'LENGTH': bad})


# --- the length -------------------------------------------------------------

def test_the_length_is_a_range_and_passwords_differ_in_length():
    assert length_range('40-50') == (40, 50) and length_range(' 24-24 ') == (24, 24)
    # one number is a fixed length (an integer too: an older setting)
    assert length_range('40') == (40, 40) and length_range(40) == (40, 40)
    lengths = {len(new_password(40, 50)) for _ in range(2000)}
    # every length of the range comes up, and nothing outside it
    assert lengths == set(range(40, 51))
    assert {len(new_password(30)) for _ in range(50)} == {30}


def test_the_page_says_the_range_and_changes_use_it(world, tmp_path):
    assert '40 to 50 characters' in world.client.get('/', headers=ME).get_data(as_text=True)
    app = create_app(world.directory, world.otp, Audit(str(tmp_path / 'b.log')),
                     {'TESTING': True, 'LENGTH': '20-21'}, notify=world.notify)
    client = app.test_client()
    assert '20 to 21 characters' in client.get('/', headers=ME).get_data(as_text=True)
    for _ in range(40):
        page = client.post('/find', headers=ME, data={'uid': 'bob'}).get_data(as_text=True)
        client.post('/change', headers=ME, data={
            'ticket': re.search(r'name="ticket" value="([^"]+)"', page).group(1)})
    assert {len(p) for p in world.otp.stored} == {20, 21}
