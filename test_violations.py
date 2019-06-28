#!/usr/bin/env python3

import main


def test_violations_add():
    """
    Tests Violations.add()
    """
    res = main.Violations()
    res.add('first', 'reason 1', {})

    assert res.results == {
        'first': [{
            'reason': 'reason 1',
            'info':   {}
        }]}
