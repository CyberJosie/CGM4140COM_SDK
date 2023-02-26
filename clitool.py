#!/usr/bin/python3
import os
import sys
import json
import time
import argparse
import textwrap
from colorama import Fore
from CoxRouterSDK import Gateway, Device

"""
These functions take the JSON results
provided by the SDK and turn them into a legible,
colored and formatted text output
"""


def get_all_devices(gw: Gateway) -> str:
    result = ''
    devices = gw.devices()
    for d in devices:
        result += d.pretty() + '\n'
    result += ' There are {} total devices'.format(len(devices))
    return result


def get_online_devices(gw: Gateway) -> str:
    result = ''
    od = gw.online_devices()
    for d in od:
        result += d.pretty() + '\n'
    result += ' There are {} connected devices'.format(len(od))
    return result


def get_offline_devices(gw: Gateway) -> str:
    result = ''
    od = gw.offline_devices()()
    for d in od:
        result += d.pretty() + '\n'
    result += ' There are {} disconnected devices'.format(len(od))
    return result


def get_network_setup_info(gw: Gateway) -> str:
    result = ''
    data = gw.network_setup()
    for d in list(data.keys()):
        result += ' > {}\n    {}\n'.format(
            '{}{}{}'.format(
                Fore.CYAN,
                d.replace('_', ' ').title(),
                Fore.RESET,
            ),
            '{}{}{}'.format(
                Fore.LIGHTYELLOW_EX,
                data[d],
                Fore.RESET,
            ))
    return result


def get_connection_status(gw: Gateway) -> str:
    result = ''
    data = gw.connection_status()

    for k in list(data.keys()):
        # Network Name Tag
        result += '{}[Network: {}]{}\n'.format(
            Fore.LIGHTCYAN_EX,
            k,
            Fore.RESET,
        )
        # Information for this network
        for sk in list(data[k].keys()):
            result += ' > {}\n    {}\n'.format(
                '{}{}{}'.format(
                    Fore.CYAN,
                    sk.replace('_', ' ').title(),
                    Fore.RESET,
                ),
                '{}{}{}'.format(
                    Fore.LIGHTYELLOW_EX,
                    data[k][sk],
                    Fore.RESET,
                ))
    return result


def main(args) -> None:
    host = '192.168.0.1'
    https_enabled = False
    verbose = False
    username = ''
    password = ''

    # Get credentials
    if args.auth_file is not None:
        try:
            with open(args.auth_file, 'r') as f:
                lines = f.read().split('\n')
                username = lines[0].strip()
                password = lines[1].strip()
        except Exception as e:
            print(' Error reading credentials from auth file!\n{}'.format(str(e)))
            exit(1)
    elif args.username is not None and args.password is not None:
        username = args.username
        password = args.password
    else:
        print('Credentials are required!')
        exit(1)

    # Get run options
    if args.verbose is not None and args.verbose is not False:
        verbose = True

    if args.use_https is not None and args.use_https is not False:
        https_enabled = True

    if args.host is not None:
        host = args.host

    # Setup Gateway client
    gw = Gateway(
        host=host,
        verbose=verbose,
        use_https=https_enabled,
    )

    # Get actions
    start = time.time()
    something_happened = False

    # List all devices
    if args.list_devices is not None and args.list_devices is not False:
        print(' Getting all devices...')
        gw.authenticate(username, password)
        result = get_all_devices(gw)
        print(result)
        something_happened = True

    # List online devices
    elif args.connected is not None and args.connected is not False:
        print(' Getting connected devices...')
        gw.authenticate(username, password)
        result = get_online_devices(gw)
        print(result)
        something_happened = True

    # List offline devices
    elif args.disconnected is not None and args.disconnected is not False:
        print(' Getting disconnected devices...')
        gw.authenticate(username, password)
        result = get_offline_devices(gw)
        print(result)
        something_happened = True

    elif args.net_setup is not None and args.net_setup is not False:
        print(' Getting network setup information...')
        gw.authenticate(username, password)
        result = get_network_setup_info(gw)
        print(result)
        something_happened = True

    elif args.conn_status is not None and args.conn_status is not False:
        print(' Getting network connection status...')
        gw.authenticate(username, password)
        result = get_connection_status(gw)
        print(result)
        something_happened = True

    if something_happened:
        # Log out
        gw.logout()
        finish = time.time()
        print(' Elapsed: {}s'.format(round(finish-start, 4)))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='CGM4140COM CLI Tool',
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent('''
        (3rd party) CLI Tool for CGM4140COM gateways.
        '''),
    )

    parser.add_argument(
        '--host', '-H',
        action='store',
        default='192.168.0.1',
        help=textwrap.dedent('''
        IP address of the gateway, default is 192.168.0.1.
        ''')
    )

    parser.add_argument(
        '--username', '-u',
        action='store',
        help=textwrap.dedent('''
        Username to authenticate with. Required in each command
        ''')
    )

    parser.add_argument(
        '--password', '-p',
        action='store',
        help=textwrap.dedent('''
        Password to authenticate with. Required in each command
        ''')
    )

    parser.add_argument(
        '--auth-file', '-a',
        action='store',
        help=textwrap.dedent('''
        Path to text file containing authentication credentials.
        First line stores username, second line store password. 
        ''')
    )

    parser.add_argument(
        '--list-devices', '-ld',
        action='store_true',
        help=textwrap.dedent('''
        Show all online and offline devices known by this gateway.
        ''')
    )

    parser.add_argument(
        '--connected', '-cd',
        action='store_true',
        help=textwrap.dedent('''
        Show all online devices known by this gateway.
        ''')
    )
    parser.add_argument(
        '--disconnected', '-dd',
        action='store_true',
        help=textwrap.dedent('''
        Show all online devices known by this gateway.
        ''')
    )

    parser.add_argument(
        '--conn-status', '-cs',
        action='store_true',
        help=textwrap.dedent('''
        Show Connection Status (General connection info for main wired and
        wireless networks)
        ''')
    )

    parser.add_argument(
        '--net-setup', '-ns',
        action='store_true',
        help=textwrap.dedent('''
        Show Network Setup Information (Advanced connection information)
        ''')
    )

    parser.add_argument(
        '--use-https', '-S',
        action='store_true',
        help=textwrap.dedent('''
        Use the routers HTTPS web service (if available, not enabled by default)
        ''')
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help=textwrap.dedent('''
        Run actions in verbose mode. Helpful for debugging
        and looking cool.
        ''')
    )

    args = parser.parse_args()
    main(args)
