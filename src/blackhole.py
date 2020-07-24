# -*- coding: utf-8 -*-
"""
Retrieve and build a formated blackhole list
"""

import logging
import argparse
import sys
import csv
import enum
import re

import requests


# exported objects
__all__ = [
    'Category',
    'ALL_CATEGORIES',
    'Quality',
    'FileRetrieveError',
    'get_masterlist',
    'filter',
    'get_blocklist'
]

#
LOG = logging.getLogger(__name__)

MASTER_CSV_URL = 'https://v.firebog.net/hosts/csv.txt'
FIELDNAMES = ['category', 'quality', 'site', 'description', 'url']


#
FQDN_PATTERN = r'(?P<fqdn>[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?(\s*#.*)?)'
IPV4_PATTERN = r'[0-9]{1,3}(\.[0-9]{1,3}){3}'
IPV6_PATTERN = r'[0-9a-f\:]+'
IP_PATTERN = r'((' + IPV4_PATTERN + r')|(' + IPV6_PATTERN + r'))'

FQDN_RE = re.compile(FQDN_PATTERN, re.I)
IP_FQDN_RE = re.compile(r'\s+'.join([IP_PATTERN, FQDN_PATTERN]), re.I)


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
    LOG.debug('Retrieving master list from {url}')

    with requests.Session() as s:
        try:
            handle = s.get(url)
            content = handle.content.decode('utf-8')

            reader = csv.DictReader(content.splitlines(), fieldnames=FIELDNAMES)    # noqa: E501

            master_list = []
            for row in reader:
                # make sure a category is present
                if 'category' not in row:
                    LOG.warn('no category found in {row}')
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
                    LOG.warn('no quality found in {row}')
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
                    LOG.warn('no description found in {row}')
                    continue

                # make sure a url is present
                if 'url' not in row:
                    LOG.warn('no description found in {row}')
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
    LOG.debug('Retrieving blocklist from {url}')

    with requests.Session() as s:
        try:
            handle = s.get(url)

            content = handle.content.decode('utf-8')

            # prepare regexes

            # process all lines one at a time
            blocklist = []
            for line in content.splitlines():
                # strip leading and following whitespace
                line = line.lstrip().rstrip()

                # ignore blank lines
                if len(line) == 0:
                    continue

                # ignore comments
                if line[0] == '#':
                    continue

                # match against FQDN pattern
                m = FQDN_RE.fullmatch(line)
                if m:
                    blocklist.append(m.group('fqdn'))
                    continue

                # match against IP + FQDN pattern
                m = IP_FQDN_RE.fullmatch(line)
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
def main():
    #
    argparser = argparse.ArgumentParser(description='Blocks Parser')

    argparser.add_argument('-d', '--debug', action='count', default=0)

    argparser.add_argument('-s', '--silent', action='store_true')

    argparser.add_argument('-u', '--url', default=MASTER_CSV_URL)

    argparser.add_argument('-c', '--category', nargs='*', default=[])
    argparser.add_argument('-q', '--quality', choices=['tick', 'std', 'cross'], default='std')      # noqa: E501

    argparser.add_argument('-f', '--format', choices=['unbound', 'bind', 'text'], default='text')   # noqa: E501
    argparser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout)       # noqa: E501

    #
    args = argparser.parse_args()

    #
    if args.debug > 0:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        LOG.debug('Debug logging enabled')

    # convert categories from strings to enums
    if len(args.category) == 0:
        categories = ALL_CATEGORIES
    else:
        categories = []
        for category in args.category:
            if category.lower() == 'suspicious':
                categories.append(Category.SUSPICIOUS)
            elif category.lower() == 'advertising':
                categories.append(Category.ADVERTISING)
            elif category.lower() == 'tracking':
                categories.append(Category.TRACKING)
            elif category.lower() == 'malicious':
                categories.append(Category.MALICIOUS)
            elif category.lower() == 'other':
                categories.append(Category.OTHER)
            else:
                LOG.error('Unknown category:  {}'.format(args.category))
                exit(-1)

    # convert quality from string to enum
    if args.quality == 'tick':
        quality = Quality.TICK
    elif args.quality == 'std':
        quality = Quality.STD
    elif args.quality == 'cross':
        quality = Quality.CROSS
    else:
        LOG.error('Unknown quality:  {}'.format(args.quality))
        exit(-1)

    # Download the Master List
    if not args.silent:
        print(f'Downloading master list from {args.url}')

    try:
        master_list = get_masterlist(args.url)
    except FileRetrieveError as msg:
        LOG.error(f'Could not retrieve master file "{args.url}":  {msg}')
        exit(-1)

    # Filter down to the specified types of FQDN lists
    filtered_list = filter(master_list, categories=categories, quality=quality)

    #
    fqdns = set()

    # Retrieve all of the FQDNs
    for row in filtered_list:
        description = row['description']
        url = row['url']

        if not args.silent:
            print(f'Downloading {url}:  {description}')

        try:
            for fqdn in get_blocklist(url):
                if fqdn not in fqdns:
                    fqdns.add(fqdn)
        except FileRetrieveError as msg:
            LOG.error(f'Could not retrieve file "{url}":  {msg}')
            exit(-1)

    # sort and print the FQDNs in the specified format
    for fqdn in sorted(fqdns):
        if args.format == 'unbound':
            args.output.write(f'local-zone: "{fqdn}" static\n')

        elif args.format == 'bind':
            LOG.error('bind output format not implemented')
            exit(-1)

        elif args.format == 'text':
            args.output.write(f'{fqdn}\n')

        else:
            LOG.error(f'Unknown output format:  {args.format}')
            exit(-1)

    #
    exit(0)


if __name__ == '__main__':
    main()

    exit(0)

# vim:sw=4:ts=4:et:fenc=utf-8:
