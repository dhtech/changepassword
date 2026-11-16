# SPDX-License-Identifier: GPL-3.0-or-later
"""The directory: find a person, set a person's password.

This machine is its own login: it binds with a TLS client certificate
(SASL EXTERNAL) and has no password of its own to keep. What that
identity may do is the directory's business - it needs to read the
people and to WRITE userPassword and shadowLastChange of a person,
nothing else (it does not need to read anybody's hash).

The password is set with the directory's own "change password"
operation (RFC 3062), so the directory hashes it its own way; this
program never makes or sees a hash. shadowLastChange is written after
it, as the day the password changed.
"""
from __future__ import annotations

import datetime
import ssl


class DirectoryError(Exception):
    pass


class Directory:
    def __init__(self, uris: list[str], base: str, cert: str, key: str, ca: str,
                 timeout: int = 10):
        self.uris, self.base = list(uris), base
        self.cert, self.key, self.ca, self.timeout = cert, key, ca, timeout

    def _connection(self):
        """A bound connection to the first directory server that takes
        one."""
        import ldap3
        from ldap3.core.exceptions import LDAPException
        try:
            tls = ldap3.Tls(local_private_key_file=self.key, local_certificate_file=self.cert,
                            ca_certs_file=self.ca, validate=ssl.CERT_REQUIRED,
                            version=ssl.PROTOCOL_TLS_CLIENT)
        except (LDAPException, OSError) as exc:
            # a certificate file that is not there, or not one
            raise DirectoryError('this machine\'s certificate: %s' % type(exc).__name__)
        problems = []
        for uri in self.uris:
            try:
                server = ldap3.Server(uri, tls=tls, connect_timeout=self.timeout)
                conn = ldap3.Connection(server, authentication=ldap3.SASL,
                                        sasl_mechanism=ldap3.EXTERNAL, sasl_credentials='',
                                        raise_exceptions=True, receive_timeout=self.timeout)
                conn.bind()
                return conn
            except (LDAPException, OSError) as exc:
                problems.append('%s: %s' % (uri, type(exc).__name__))
        raise DirectoryError('no directory server took the connection (%s)'
                             % '; '.join(problems))

    def find(self, uid: str) -> dict | None:
        """{'dn', 'uid', 'name'} of the person called UID, or None."""
        import ldap3
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars
        conn = self._connection()
        try:
            conn.search(self.base, '(&(objectClass=posixAccount)(uid=%s))'
                        % escape_filter_chars(uid), ldap3.SUBTREE, attributes=['uid', 'cn'])
            found = [e for e in conn.response or [] if e.get('type') == 'searchResEntry']
        except LDAPException as exc:
            raise DirectoryError('search: %s' % type(exc).__name__)
        finally:
            _close(conn)
        if len(found) != 1:
            # nobody - or more than one, which is nobody to change
            return None
        attrs = found[0]['attributes']
        return {'dn': found[0]['dn'], 'uid': _one(attrs.get('uid')) or uid,
                'name': _one(attrs.get('cn')) or ''}

    def set_password(self, dn: str, password: str) -> None:
        from ldap3 import MODIFY_REPLACE
        from ldap3.core.exceptions import LDAPException
        conn = self._connection()
        try:
            try:
                conn.extend.standard.modify_password(user=dn, new_password=password)
            except LDAPException as exc:
                raise DirectoryError('change password: %s' % type(exc).__name__)
            # the password IS changed from here on: the day it changed is
            # worth having, and not worth calling the change a failure for
            try:
                conn.modify(dn, {'shadowLastChange': [(MODIFY_REPLACE, [str(today())])]})
            except LDAPException:
                pass
        finally:
            _close(conn)


def today() -> int:
    """Days since 1970-01-01, as shadowLastChange counts."""
    return (datetime.datetime.now(datetime.timezone.utc).date()
            - datetime.date(1970, 1, 1)).days


def _one(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _close(conn) -> None:
    try:
        conn.unbind()
    except Exception:
        pass
