# -*- coding: utf-8 -*-
"""
Retrieve and build a formated blackhole list
"""

import logging
import csv
import enum
import re

import requests


#
LOG = logging.getLogger(__name__)

MASTER_CSV_URL = 'https://v.firebog.net/hosts/csv.txt'
FIELDNAMES = ['category', 'quality', 'site', 'description', 'url']


#
class Category(enum.Enum):
    SUSPICIOUS = enum.auto()
    ADVERTISING = enum.auto()
    TRACKING = enum.auto()
    MALICIOUS = enum.auto()
    OTHER = enum.auto()


#
ALL_CATEGORIES = [
    Category.SUSPICIOUS,
    Category.ADVERTISING,
    Category.TRACKING,
    Category.MALICIOUS,
    Category.OTHER,
]


#
class Quality(enum.IntEnum):
    CROSS = 1
    STD = 2
    TICK = 3


#
class FileRetrieveError(IOError):
    pass


#
def get_masterlist(url=MASTER_CSV_URL):
    LOG.debug(f'Retrieving master list from {url}')

    with requests.Session() as s:
        try:
            handle = s.get(url)
            content = handle.content.decode('utf-8')

            reader = csv.DictReader(content.splitlines(), fieldnames=FIELDNAMES)    # noqa: E501

            master_list = []
            for row in reader:
                # make sure a category is present
                if 'category' not in row:
                    LOG.warn(f'no category found in {row}')
                    continue

                # convert the row's category to the enum type
                if row['category'] == 'suspicious':
                    row['category'] = Category.SUSPICIOUS
                elif row['category'] == 'advertising':
                    row['category'] = Category.ADVERTISING
                elif row['category'] == 'tracking':
                    row['category'] = Category.TRACKING
                elif row['category'] == 'malicious':
                    row['category'] = Category.MALICIOUS
                elif row['category'] == 'other':
                    row['category'] = Category.OTHER
                else:
                    LOG.warn('Skipping unknown category:  {} in {}'.format(row['category'], row))       # noqa: E501
                    continue

                # make sure a quality is present
                if 'quality' not in row:
                    LOG.warn(f'no quality found in {row}')
                    continue

                # convert the row's quality to the enum type
                if row['quality'] == 'cross':
                    row['quality'] = Quality.CROSS
                elif row['quality'] == 'std':
                    row['quality'] = Quality.STD
                elif row['quality'] == 'tick':
                    row['quality'] = Quality.TICK
                else:
                    LOG.warn('Skipping unknown quality:  {} in {}'.format(row['quality'], row))     # noqa: E501
                    continue

                # make sure a description is present
                if 'description' not in row:
                    LOG.warn(f'no description found in {row}')
                    continue

                # make sure a url is present
                if 'url' not in row:
                    LOG.warn(f'no description found in {row}')
                    continue

                #
                master_list.append(row)

        except IOError as msg:
            raise FileRetrieveError(msg)

        return master_list


#
def filter(master_list, categories=ALL_CATEGORIES, quality=Quality.STD):
    assert isinstance(categories, (list, tuple))

    for category in categories:
        assert isinstance(category, Category)

    assert isinstance(quality, Quality)

    filtered_urls = []

    for row in master_list:
        # filter by category
        if row['category'] not in categories:
            continue

        # filter by quality
        if row['quality'] < quality:
            continue

        #
        filtered_urls.append(row)

    return filtered_urls


#
def get_blocklist(url):
    LOG.debug(f'Retrieving blocklist from {url}')

    #
    fqdn_pattern = r'(?P<fqdn>[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.[a-z][a-z0-9_-]*[a-z])\.?)' # noqa: E501
    ipv4_pattern = r'[0-9]{1,3}(\.[0-9]{1,3}){3}'
    ipv6_pattern = r'[0-9a-f\:]+'
    ip_pattern = r'((' + ipv4_pattern + r')|(' + ipv6_pattern + r'))'

    fqdn_re = re.compile(fqdn_pattern, re.I)
    ip_fqdn_re = re.compile(r'\s+'.join([ip_pattern, fqdn_pattern]), re.I)

    #
    with requests.Session() as s:
        try:
            handle = s.get(url)

            content = handle.content.decode('utf-8')

            # prepare regexes

            # process all lines one at a time
            blocklist = []
            for line in content.splitlines():
                # strip off any comments
                line = line.split('#')[0]

                # strip leading and following whitespace
                line = line.lstrip().rstrip()

                # ignore blank lines
                if len(line) == 0:
                    continue

                # ignore comments
                # if line[0] == '#':
                #     continue

                # slamcase to lower
                line = line.lower()

                # match against FQDN pattern
                m = fqdn_re.fullmatch(line)
                if m:
                    blocklist.append(m.group('fqdn'))
                    continue

                # match against IP + FQDN pattern
                m = ip_fqdn_re.fullmatch(line)
                if m:
                    blocklist.append(m.group('fqdn'))
                    continue

                #
                LOG.warning(f'no FQDN pattern matched:  {line}')

        except requests.exceptions.RequestException as msg:
            raise FileRetrieveError(msg)

        #
        return blocklist


#
def create_adjustments(adjustments, allow_regexes=True):
    assert isinstance(adjustments, (tuple, list))
    for adj in adjustments:
        assert isinstance(adj, str)

    #
    fqdn_pattern = r'(?P<fqdn>[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.[a-z][a-z0-9_-]*[a-z])\.?)' # noqa: E501
    fqdn_re = re.compile(fqdn_pattern, re.I)

    #
    fqdns = set()
    regexes = []

    for adj in adjustments:
        if adj[0] == '@':
            with open(adj[1:], 'r') as f:
                more_adjs = f.readlines()

            (nfqdns, nregexes) = create_adjustments(more_adjs)

            fqdns = fqdns.union(nfqdns)
            regexes.extend(nregexes)

        elif allow_regexes and adj.find('/') != -1:
            parts = adj.split('/')

            if len(parts) != 3:
                LOG.warning(f'skipping malformed regex adjustment:  {adj}')
                continue

            (_, pattern, modifiers) = parts

            flags = 0
            if len(modifiers) > 0:
                if 'a' in modifiers:
                    flags |= re.A
                elif 'i' in modifiers:
                    flags |= re.I
                elif 'l' in modifiers:
                    flags |= re.L
                else:
                    LOG.warning(f'unknown regex modifier in regex adjustment:  {adj}')       # noqa: E501
                    continue

            adj_re = re.compile(pattern, flags)

            regexes.append((adj, adj_re))

        else:
            m = fqdn_re.fullmatch(adj)
            if not m:
                LOG.warning(f'skipping malformed FQDN adjustment:  {adj}')       # noqa: E501
                continue

            fqdns.add(adj)

    return (fqdns, regexes)


#
def make_adjustments(fqdns, includes=None, excludes=None):
    assert isinstance(includes, (tuple, list))
    assert len(includes) == 2
    assert len(includes[1]) == 0

    assert isinstance(excludes, (tuple, list))
    assert len(excludes) == 2

    nfqdns = set()

    # process excludes
    (efqdns, eregexes) = excludes
    for fqdn in fqdns:
        skip = False

        # check static FQDNs first
        for efqdn in efqdns:
            if fqdn == efqdn:
                skip = True
                break

        # check regex FQDNs next
        for eregex in eregexes:
            (pattern, compiled_re) = eregex

            m = compiled_re.fullmatch(fqdn)
            if m:
                skip = True
                break

        if not skip:
            nfqdns.add(fqdn)

    # process includes
    (ifqdns, _) = includes
    for ifqdn in ifqdns:
        nfqdns.add(ifqdn)

    #
    return nfqdns

# vim:sw=4:ts=4:et:fenc=utf-8:
