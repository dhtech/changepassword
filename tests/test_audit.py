# SPDX-License-Identifier: GPL-3.0-or-later
import json

import pytest

from changepassword.audit import Audit


def test_one_line_per_attempt_newest_first(tmp_path):
    audit = Audit(str(tmp_path / 'audit.log'))
    assert audit.latest(10) == []
    audit.record(changer='a', target='x', address='10.0.0.1', outcome='changed', link='id-1')
    audit.record(changer='b', target='y', address='10.0.0.2', outcome='failed',
                 detail='the directory did not take the password')
    lines = open(audit.path).read().splitlines()
    assert len(lines) == 2 and all(json.loads(line)['at'].endswith('+00:00') for line in lines)
    newest, older = audit.latest(10)
    assert (newest['changer'], newest['outcome'], newest['link']) == ('b', 'failed', '')
    assert (older['changer'], older['target'], older['link']) == ('a', 'x', 'id-1')
    assert [e['changer'] for e in audit.latest(1)] == ['b']


def test_nothing_else_gets_into_a_line(tmp_path):
    audit = Audit(str(tmp_path / 'audit.log'))
    audit.record(changer='a', target='x', address='', outcome='changed', password='NEVER',
                 key='NEVER')
    assert 'NEVER' not in open(audit.path).read()


def test_a_broken_line_is_skipped_and_a_missing_directory_is_said(tmp_path):
    audit = Audit(str(tmp_path / 'audit.log'))
    audit.record(changer='a', target='x', address='', outcome='changed')
    with open(audit.path, 'a') as handle:
        handle.write('not json\n')
    assert len(audit.latest(10)) == 1
    with pytest.raises(OSError):
        Audit(str(tmp_path / 'no' / 'dir' / 'audit.log')).check()
