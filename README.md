# changepassword

Give somebody in the directory a new password - without anybody typing,
choosing or seeing it.

An authorised person opens the page, names a user and confirms. The
program then

1. makes a random password (40 letters and digits by default),
2. encrypts it and puts it into a one-time link service
   ([Yopass](https://github.com/jhaals/yopass)) - the service keeps
   ciphertext only, the key is in the link,
3. sets it in the LDAP directory with the directory's own "change
   password" operation (RFC 3062; the directory does the hashing),
4. shows the changer **the link** - once. Whoever opens the link first
   sees the password; then it is gone.

Nothing is changed unless the link exists first. Every attempt is
written to a log (who, whose, when, from where - never the password or
the link's key), shown on the page "Log", and told to a Discord channel
when a webhook is configured.

## Who is allowed

changepassword does not log anybody in and does not decide who may
change passwords. A reverse proxy in front does both and hands over the
name in `X-Remote-User` (and the visitor's address in `X-Real-IP`).
The program listens on the loopback address, believes those headers and
refuses every page without a name. `/healthz` is the one page without.

Changing takes two steps - find, then confirm - and the second takes
nothing but a signed ticket the first made for this changer and that
person, good for five minutes.

## The directory

The program binds with a TLS client certificate (SASL EXTERNAL); it has
no password of its own. The directory must let that identity read the
people and **write** `userPassword` and `shadowLastChange` of a person.
It does not need to read anybody's hash.

## Settings (environment)

| Variable | What |
|---|---|
| `CHANGEPASSWORD_LDAP_URIS` | the directory servers to write to, in order (`ldaps://...`, separated by spaces) |
| `CHANGEPASSWORD_LDAP_BASE` | where the people are |
| `CHANGEPASSWORD_LDAP_CERT`, `_LDAP_KEY`, `_LDAP_CA` | this machine's certificate and key, and the CA of the directory servers |
| `CHANGEPASSWORD_OTP_API` | where links are made (Yopass's API) |
| `CHANGEPASSWORD_OTP_URL` | where people open links |
| `CHANGEPASSWORD_LINK_LIFE` | seconds an unopened link lives: 3600, 86400 (default) or 604800 |
| `CHANGEPASSWORD_LENGTH` | the password's length (default 40, at least 20) |
| `CHANGEPASSWORD_AUDIT` | the log file |
| `CHANGEPASSWORD_DISCORD_FILE` | a file holding a Discord webhook address (optional; read for every message) |
| `CHANGEPASSWORD_KEY_FILE` | a file with at least 32 random bytes: what the tickets are signed with |
| `CHANGEPASSWORD_TIMEZONE`, `CHANGEPASSWORD_TITLE` | for the pages |

It needs `gpg` on the machine (the encryption is GnuPG's, in the form
Yopass itself writes), Flask and ldap3.

    gunicorn --bind 127.0.0.1:8000 changepassword.wsgi:app

## Tests

    pip install '.[test]' && pytest

The link tests encrypt with the real `gpg` and are skipped without it.
