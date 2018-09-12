#!/usr/bin/env python3

import argparse
import fileinput
import sys
import os

DBUS_SEND_DICT = {'n': 'int16',
                  'q': 'unit16',
                  'i': 'int32',
                  'u': 'uint32',
                  'x': 'int64',
                  't': 'uint64',
                  'd': 'double',
                  'y': 'byte',
                  'b': 'boolean'}

DBUS_SEND_STRINGS_DICT = {'s': 'string',
                          'o': 'objpath'}

def dbus_send_format(args):
    ret = ""
    for arg in args:
        if arg[0] == '/':
            continue
        if arg[0] in DBUS_SEND_DICT:
            ret += "{}:{} ".format(DBUS_SEND_DICT[arg[0]], arg[1])
        elif arg[0] in DBUS_SEND_STRINGS_DICT:
            ret += '{}:"`echo {} | xxd -r -p`" '.format(
                    DBUS_SEND_STRINGS_DICT[arg[0]], arg[1])
        else:
            print("Argument type {} unsupported for dbus_send".format(arg[0]),
                    file=sys.stderr)
            return []
    return ret

def dbus_send(bus, name, iface, obj, method, args):
    print("dbus-send --{} --dest={} --print-reply {} {}.{} {}"
            .format(bus, name, obj, iface, method, dbus_send_format(args)))

def gdbus_format(args):
    ret = ""
    print(args, file=sys.stderr)
    for arg in args:
        if arg[0] == '/':
            continue
        if arg[0] in 'sogv':
            ret += '"`echo {} | xxd -r -p`" '.format(arg[1])
        else:
            ret += "{} ".format(arg[1])
    return ret

def gdbus(bus, name, iface, obj, method, args):
    print("gdbus call --{} --dest {} --object-path {} --method {}.{} {}"
            .format(bus, name, obj, iface, method, gdbus_format(args)))

def main(bus, process, name_for_stdin, results_filter, files):
    if name_for_stdin is None and '-' in files:
        return False
    for line in fileinput.input(files):
        parsed_line = line.strip().split(';');
        if parsed_line[-1] not in results_filter:
            continue
        process(bus, name_for_stdin if fileinput.isstdin()
                else os.path.basename(fileinput.filename()), parsed_line[0],
                parsed_line[1], parsed_line[2], [parsed_line[i:i+2]
                    for i in range(1, len(parsed_line)-1,2)])
    return True

if __name__ == '__main__':
    functions = {'dbus-send': dbus_send, 'gdbus': gdbus}
    p = argparse.ArgumentParser(
            description='Generate reproduction code from dfuzzer logs')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--system',  action='store_true', help='Use system bus')
    g.add_argument('--session', action='store_true', help='Use session bus')
    p.add_argument('-t', '--target', choices=['dbus-send', 'gdbus'],
            default='dbus-send', help='Target language/library')
    p.add_argument('-n', '--name', type=str, default=None,
            help='Name of the bus to use when taking input from stdin')
    p.add_argument('-f', '--filter', type=str, choices=['Crash','Success',
        'Command execution error'], default='[Crash]', nargs='+',help=
        'List of result types for which reproduction code will be generated')
    p.add_argument('files', type=str, nargs='+',
            help='Paths to log files ("-" for stdin)')
    args = p.parse_args()
    if not main('system' if args.system else 'session', functions[args.target],
            args.name, args.filter, args.files):
        p.print_usage(file=sys.stderr)
        print('{}: When taking input from stdin, you must specify bus name'
                .format(sys.argv[0]))
        exit(2)
