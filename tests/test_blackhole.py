# -*- coding: utf-8 -*-
"""
blackhole/tests/tests.py
"""

import pytest
import re

from itertools import chain, combinations

import blackhole


CATEGORIES = list(blackhole.Category)
QUALITIES = list(sorted(blackhole.Quality))


@pytest.fixture
def master_list():
    return blackhole.get_masterlist()


def test_get_masterlist(master_list):
    assert len(master_list) > 1

    for row in master_list:
        assert len(row) == 5

        assert 'category' in row
        assert isinstance(row['category'], blackhole.Category)

        assert 'quality' in row
        assert isinstance(row['quality'], blackhole.Quality)

        assert 'site' in row
        assert isinstance(row['site'], str)
        assert len(row['site']) > 0

        assert 'description' in row
        assert isinstance(row['description'], str)
        assert len(row['description']) > 0

        assert 'url' in row
        assert isinstance(row['url'], str)
        assert len(row['url']) > 0


def test_filter(master_list):

    # from https://stackoverflow.com/questions/464864/how-to-get-all-possible-combinations-of-a-list-s-elements # noqa: E501
    all_categories = chain(*map(lambda x: combinations(CATEGORIES, x), range(0, len(CATEGORIES) + 1)))  # noqa: E501

    for categories in all_categories:
        for quality in QUALITIES:
            filtered_list = blackhole.filter(master_list, categories=categories, quality=quality)       # noqa: E501

            for row in filtered_list:
                assert row['category'] in categories
                assert row['quality'] >= quality


def test_get_blocklist(master_list):
    fqdn_pattern = r'(?P<fqdn>[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?(\s*#.*)?)'
    fqdn_re = re.compile(fqdn_pattern, re.I)

    quality = blackhole.Quality.TICK

    for category in CATEGORIES:
        filtered_list = blackhole.filter(master_list, categories=[category], quality=quality)           # noqa: E501

        url = filtered_list[0]['url']

        blocklist = blackhole.get_blocklist(url)

        assert len(blocklist) > 0

        for fqdn in blocklist:
            m = fqdn_re.fullmatch(fqdn)

            assert m
            assert fqdn == m.group('fqdn')


def test_adjustments():
    fqdns = set(['abc.com', 'def.ab.com', 'def.com', 'dee.net', 'Deg.org'])
    includes = ['ghi.com', 'xyz.com']
    excludes = ['def.com', 'lmn.net', r'/de.\.(com|net|org)/', r'/de.\.(com|net|org)/i']            # noqa: E501

    incl_adjs = blackhole.create_adjustments(includes, allow_regexes=False)
    excl_adjs = blackhole.create_adjustments(excludes, allow_regexes=True)

    nfqdns = blackhole.make_adjustments(fqdns, incl_adjs, excl_adjs)

    assert len(nfqdns) == 4

# vim:sw=4:ts=4:et:fenc=utf-8:
