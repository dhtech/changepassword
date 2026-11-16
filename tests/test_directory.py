# SPDX-License-Identifier: GPL-3.0-or-later
"""The directory calls, with a stand-in connection. (Against a real
slapd: contrib/try-slapd.sh.)"""
import datetime

import pytest

pytest.importorskip('ldap3')

from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult  # noqa: E402

from changepassword import directory  # noqa: E402

DN = 'uid=bob,ou=people,dc=example'


class Extend:
    def __init__(self, conn):
        self.standard = self
        self.conn = conn

    def modify_password(self, user, new_password):
        if self.conn.refuse_password:
            raise LDAPInsufficientAccessRightsResult('no')
        self.conn.calls.append(('password', user, new_password))
        return True


class Conn:
    def __init__(self, entries=()):
        self.entries, self.calls = list(entries), []
        self.refuse_password = self.refuse_modify = False
        self.extend = Extend(self)
        self.response = None

    def search(self, base, flt, scope, attributes):
        self.calls.append(('search', base, flt))
        self.response = self.entries

    def modify(self, dn, changes):
        if self.refuse_modify:
            raise LDAPInsufficientAccessRightsResult('no')
        self.calls.append(('modify', dn, changes))

    def unbind(self):
        self.calls.append(('unbind',))


def the(conn):
    d = directory.Directory(['ldaps://one'], 'ou=people,dc=example', 'c', 'k', 'ca')
    d._connection = lambda: conn
    return d


def entry(uid='bob', cn='Bob Example', dn=DN):
    return {'type': 'searchResEntry', 'dn': dn, 'attributes': {'uid': [uid], 'cn': [cn]}}


def test_one_person_is_found_and_the_name_cannot_widen_the_search():
    conn = Conn([entry(), {'type': 'searchResRef'}])
    assert the(conn).find('bob') == {'dn': DN, 'uid': 'bob', 'name': 'Bob Example'}
    conn = Conn([])
    assert the(conn).find('a)(uid=*') is None
    assert conn.calls[0][2] == '(&(objectClass=posixAccount)(uid=a\\29\\28uid=\\2a))'
    assert conn.calls[-1] == ('unbind',)


def test_two_by_one_name_is_nobody():
    assert the(Conn([entry(), entry(dn='uid=bob,ou=other,dc=example')])).find('bob') is None


def test_the_password_goes_in_by_the_directorys_own_operation():
    conn = Conn()
    the(conn).set_password(DN, 'N3w')
    days = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.date(1970, 1, 1)).days
    assert conn.calls[0] == ('password', DN, 'N3w')
    assert conn.calls[1][:2] == ('modify', DN)
    assert list(conn.calls[1][2]) == ['shadowLastChange']
    assert conn.calls[1][2]['shadowLastChange'][0][1] == [str(days)]
    assert conn.calls[-1] == ('unbind',)


def test_a_refused_password_is_a_failure_a_refused_date_is_not():
    conn = Conn()
    conn.refuse_password = True
    with pytest.raises(directory.DirectoryError):
        the(conn).set_password(DN, 'N3w')
    assert [c[0] for c in conn.calls] == ['unbind']
    conn = Conn()
    conn.refuse_modify = True
    the(conn).set_password(DN, 'N3w')
    assert [c[0] for c in conn.calls] == ['password', 'unbind']


def test_no_certificate_or_no_server_is_a_directory_error(tmp_path):
    # the real library, nothing to connect to
    none = str(tmp_path / 'none.pem')
    with pytest.raises(directory.DirectoryError, match='certificate'):
        directory.Directory(['ldaps://127.0.0.1:1'], 'ou=people', none, none, none).find('x')
    with pytest.raises(directory.DirectoryError):
        directory.Directory(['ldaps://127.0.0.1:1'], 'ou=people', none, none, none
                            ).set_password('uid=x', 'y')
