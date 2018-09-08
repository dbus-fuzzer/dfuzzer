#!/usr/bin/env python3

import argparse
import sys

def main(bus, target, name_for_stdin, files):
    if name_for_stdin is None and '-' in files:
        return False
    return True

if __name__ == '__main__':
    p = argparse.ArgumentParser(
            description='Generate reproduction code from dfuzzer logs')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--system',  action='store_true', help='Use system bus')
    g.add_argument('--session', action='store_true', help='Use session bus')
    p.add_argument('-t', '--target', choices=['dbus-send'],
            default='dbus-send', help='Target language/library')
    p.add_argument('-n', '--name', type=str, default=None,
            help='Name of the bus to use when taking input from stdin')
    p.add_argument('files', type=str, nargs='+',
            help='Paths to log files ("-" for stdin)')
    args = p.parse_args()
    if not main('system' if args.system else 'session', args.target, args.name,
            args.files):
        p.print_usage(file=sys.stderr)
        print('{}: When taking input from stdin, you must specify bus name'
                .format(sys.argv[0]))
        exit(2)
