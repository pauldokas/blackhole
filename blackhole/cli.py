# -*- coding: utf-8 -*-
"""
Retrieve and build a formated blackhole list
"""

import logging
import argparse
import sys

import blackhole


#
def main():
    #
    log = logging.getLogger(__name__)

    #
    argparser = argparse.ArgumentParser(description='Blocks Parser')

    argparser.add_argument('-d', '--debug', action='count', default=0)

    argparser.add_argument('-s', '--silent', action='store_true')

    argparser.add_argument('-u', '--url', default=blackhole.MASTER_CSV_URL)

    argparser.add_argument('-c', '--category', nargs='*', default=[])
    argparser.add_argument('-q', '--quality', choices=['tick', 'std', 'cross'], default='std')      # noqa: E501

    argparser.add_argument('-f', '--format', choices=['unbound', 'bind', 'text'], default='text')   # noqa: E501
    argparser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout)       # noqa: E501

    #
    args = argparser.parse_args()

    #
    if args.debug > 0:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        log.debug('Debug logging enabled')

    # convert categories from strings to enums
    if len(args.category) == 0:
        categories = blackhole.ALL_CATEGORIES
    else:
        categories = []
        for category in args.category:
            if category.lower() == 'suspicious':
                categories.append(blackhole.Category.SUSPICIOUS)
            elif category.lower() == 'advertising':
                categories.append(blackhole.Category.ADVERTISING)
            elif category.lower() == 'tracking':
                categories.append(blackhole.Category.TRACKING)
            elif category.lower() == 'malicious':
                categories.append(blackhole.Category.MALICIOUS)
            elif category.lower() == 'other':
                categories.append(blackhole.Category.OTHER)
            else:
                log.error('Unknown category:  {}'.format(args.category))
                exit(-1)

    # convert quality from string to enum
    if args.quality == 'tick':
        quality = blackhole.Quality.TICK
    elif args.quality == 'std':
        quality = blackhole.Quality.STD
    elif args.quality == 'cross':
        quality = blackhole.Quality.CROSS
    else:
        log.error('Unknown quality:  {}'.format(args.quality))
        exit(-1)

    # Download the Master List
    if not args.silent:
        print(f'Downloading master list from {args.url}')

    try:
        master_list = blackhole.get_masterlist(args.url)
    except blackhole.FileRetrieveError as msg:
        log.error(f'Could not retrieve master file "{args.url}":  {msg}')
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
            for fqdn in blackhole.get_blocklist(url):
                if fqdn not in fqdns:
                    fqdns.add(fqdn)
        except blackhole.FileRetrieveError as msg:
            log.error(f'Could not retrieve file "{url}":  {msg}')
            exit(-1)

    # sort and print the FQDNs in the specified format
    for fqdn in sorted(fqdns):
        if args.format == 'unbound':
            args.output.write(f'local-zone: "{fqdn}" static\n')

        elif args.format == 'bind':
            log.error('bind output format not implemented')
            exit(-1)

        elif args.format == 'text':
            args.output.write(f'{fqdn}\n')

        else:
            log.error(f'Unknown output format:  {args.format}')
            exit(-1)

    #
    exit(0)


if __name__ == '__main__':
    main()

    exit(0)

# vim:sw=4:ts=4:et:fenc=utf-8:
