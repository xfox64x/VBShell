#!/usr/bin/env python
# -*- coding: utf-8 -*-

# I don't know why I kept any of the original Jackit script...

from __future__ import print_function, absolute_import
from six import iteritems
import os
import sys
import jackit
import json
import time
import datetime
import platform
import click
import tabulate
import array
from jackit import duckyparser
from jackit import mousejack
from jackit import keylogger
from jackit import plugins


__version__ = 1.01
__authors__ = "phikshun, infamy, forrest"
__attack_log_path__ = "jhackit_attack_log.json"
__attack_log__ = {}

# some console colours
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

def read_attack_log():
    global __attack_log__
    try:
        if os.path.isfile(__attack_log_path__):
            with open(__attack_log_path__, 'r') as f:
                __attack_log__ = json.load(f)
        else:
            __attack_log__ = {}
    except:
        pass

def update_attack_log():
    #print("Updating attack log...")
    global __attack_log__
    try:
        if __attack_log__:
            with open(__attack_log_path__, 'w') as f:
                f.write(json.dumps(__attack_log__, cls=ComplexEncoder, sort_keys=True, indent=4))
    except:
        pass

def do_attack(jack, addr_string, target, payload="", use_ping=True):
    global __attack_log__

    payload  = target['payload']
    channels = target['channels']
    address  = target['address']
    hid      = target['device']
    if addr_string not in __attack_log__:
        __attack_log__[addr_string] = {}
        __attack_log__[addr_string]['address'] = address
        __attack_log__[addr_string]['locked_channel'] = False
        __attack_log__[addr_string]['pinged'] = False 
        __attack_log__[addr_string]['attacked'] = False 
        __attack_log__[addr_string]['no_hid'] = False 
        __attack_log__[addr_string]['attack_successful'] = False 
        __attack_log__[addr_string]['ping_successful'] = False 
        __attack_log__[addr_string]['last_attacked'] = datetime.datetime.min
        __attack_log__[addr_string]['last_pinged'] = datetime.datetime.min
        __attack_log__[addr_string]['last_successful_attack'] = datetime.datetime.min
        __attack_log__[addr_string]['last_successful_ping'] = datetime.datetime.min

    __attack_log__[addr_string]['channels'] = channels
    __attack_log__[addr_string]['last_seen'] = datetime.datetime.fromtimestamp(target['timestamp'])
    
    # Sniffer mode allows us to spoof the address
    jack.sniffer_mode(address)

    if not hid:
        if not __attack_log__[addr_string]['no_hid']:
            print(R + '[-] ' + W + "Target %s is not injectable. Temporarily skipping..." % (addr_string))
        __attack_log__[addr_string]['no_hid'] = True 
        #del __attack_log__[addr_string]
        return
   
    __attack_log__[addr_string]['no_hid'] = False 
    __attack_log__[addr_string]['description'] = hid.description()
    
    # Attempt to ping the devices to find the current channel
    lock_channel = False
    if use_ping:
        __attack_log__[addr_string]['pinged'] = True 
        __attack_log__[addr_string]['last_pinged'] = datetime.datetime.now()
        lock_channel = jack.find_channel(address)
    __attack_log__[addr_string]['locked_channel'] = lock_channel

    if lock_channel:
        print("[!] Attacking {}...".format(addr_string))
        __attack_log__[addr_string]['ping_successful'] = True 
        __attack_log__[addr_string]['last_successful_ping'] = __attack_log__[addr_string]['last_pinged']
        print(G + '[+] ' + W + 'Ping success on channel %d' % (lock_channel,))
        __attack_log__[addr_string]['attacked'] = True
        #print(GR + '[+] ' + W + 'Sending attack to %s [%s] on channel %d' % (addr_string, hid.description(), lock_channel))
        #jack.attack(hid(address, payload), attack)
    
    #else:
        # If our pings fail, go full hail mary
        #print(R + '[-] ' + W + 'Ping failed, trying all channels')
        #for channel in channels:
            #jack.set_channel(channel)
            #print(GR + '[+] ' + W + 'Sending attack to %s [%s] on channel %d' % (addr_string, hid.description(), channel))
            #jack.attack(hid(address, payload), attack)


class ComplexEncoder(json.JSONEncoder):
    def default(self, o):
        if type(o) == type(jackit.plugins.logitech.HID):
            return 'Logitech'

        elif type(o) == type(jackit.plugins.microsoft.HID):
            return 'Microsoft'

        elif type(o) == type(jackit.plugins.amazon.HID):
            return 'Amazon'
        
        elif type(o) == type(jackit.plugins.microsoft_enc.HID):
            return 'Microsoft (Encrypted)'

        #elif str(type(o)) == "<type, 'dictproxy'>":
            #return json.JSONEncoder.default(self, dict(o))
            
        #elif isinstance(o, complex):
            #return [o.real, o.imag]

        #elif isinstance(o, type):
            #return [o.real, o.imag]
        
        elif isinstance(o, array.array):
            return list(iter(o))
        
        elif isinstance(o, datetime.datetime):
            return str(o)
        
        try:
            return json.JSONEncoder.default(self,o)
        
        except TypeError:
            return str(type(o))


def scan_loop(jack, interval, address=None):
    last_device_count = len(jack.devices)

    if address and address.strip() != "":
        jack.sniff(interval, address)
    else:
        jack.scan(interval)

    #x = (json.dumps(jack.devices, cls=ComplexEncoder, skipkeys=True, sort_keys=True, indent=4))
    
    for addr_string, device in iteritems(jack.devices):
        if device['device']:
            device_name = device['device'].description()
        else:
            device_name = 'Unknown'
    
    if len(jack.devices) > last_device_count:
        print("[+] Found +{} new device(s) [{} total]".format(len(jack.devices)-last_device_count, len(jack.devices)))

    
def _print_err(text):
    print(R + '[!] ' + W + text)

def banner():
    print("JackIt Version %0.2f" % __version__)
    print("Created by %s\n" % __authors__)

def confirm_root():
    # make sure we are root
    if os.getuid() != 0 and platform.system() != 'Darwin':
        _print_err("ERROR: You need to run as root!")
        _print_err("login as root (su root) or try sudo %s" % sys.argv[0])
        exit(-1)


@click.command()
@click.option('--debug', is_flag=True, help='Enable debug.')
@click.option('--script', default="", help="Ducky file to use for injection.", type=click.Path())
@click.option('--lowpower', is_flag=True, help="Disable LNA on CrazyPA.")
@click.option('--interval', default=5, help="Interval of scan in seconds, default to 5s.")
@click.option('--layout', default='us', help="Keyboard layout: us, gb, de...")
@click.option('--address', default="", help="Address of device to target attack.")
@click.option('--vendor', default="", help="Vendor of device to target (required when specifying address).")
@click.option('--no-reset', is_flag=True, help="Reset CrazyPA dongle prior to initalization.")
@click.option('--keep-attacking', is_flag=True, help="Keep attacking any previously attacked hosts.")
@click.option('--all-channels', is_flag=True, help="Send attack to all detected channels.")
@click.option('--whitelist-path', default="", help="White-list of specific devices to attack.")
@click.option('--blacklist-path', default="", help="Black-list of specific devices to skip attacking.")
def cli(debug, script, lowpower, interval, layout, address, vendor, no_reset, keep_attacking, all_channels, whitelist_path, blacklist_path):
    global __attack_log__
    read_attack_log()
    banner()
    confirm_root()

    whitelist = []
    blacklist = []

    if address and not vendor:
        _print_err("Please use --vendor option to specify either Logitech, Microsoft or Amazon.")
        exit(-1)

    elif vendor and not address:
        _print_err("Please use --address option when specifying a vendor.")
        exit(-1)
    
    elif vendor and address:
        vendor = vendor.lower()
        if not vendor.startswith("l") and not vendor.startswith("m") and not vendor.startswith("a"):
            _print_err("Unknown vendor: specify either Microsoft, Logitech or Amazon.")
            exit(-1)
    
    if whitelist_path and os.path.isfile(whitelist_path):
        with open(whitelist_path, "r") as f:
            whitelist = map(lambda x: x.strip().upper(), filter(lambda y: y.strip() != "", f.readlines()))
        if len(whitelist) > 0:
            print(O+"[!] "+W+("Using a whitelist consisting of {} device(s)...".format(len(whitelist))))

    if blacklist_path and os.path.isfile(blacklist_path):
        with open(blacklist_path, "r") as f:
            blacklist = map(lambda x: x.strip().upper(), filter(lambda y: y.strip() != "", f.readlines()))
        if len(blacklist) > 0:
            print(O+"[!] "+W+("Using a blacklist consisting of {} device(s)...".format(len(blacklist))))

    attack = ""
    
    try:
        jack = mousejack.MouseJack(lowpower, debug, (not no_reset))
    except Exception as e:
        if e.__str__() == "Cannot find USB dongle.":
            _print_err("Cannot find Crazy PA USB dongle.")
            _print_err("Please make sure you have it preloaded with the mousejack firmware.")
            exit(-1)
        else:
            raise e

    if address and address.strip() != "":
        print(GR+"[+] "+W+("Sniffing for %s every %ds " % (address, interval))+G+"CTRL-C "+W+"when done.\n")
    else:
        print(GR+"[+] "+W+("Scanning every %ds " % interval)+G+"CTRL-C "+W+"when done.\n")

    try:
        while True:
            scan_loop(jack, interval, address)
            for addr_string, device in iteritems(jack.devices):
                
                # If a whitelist was used, don't attack anything not in the whitelist
                if len(whitelist) > 0 and addr_string not in whitelist:
                    continue

                # If a blacklist was used, don't attack anything in the blacklist
                if len(blacklist) > 0 and addr_string in blacklist:
                    continue

                # Only attack things that haven't been attacked, unless keep-attacking was specified
                if addr_string not in __attack_log__ or not __attack_log__[addr_string]['attacked'] or keep_attacking:
                    do_attack(jack, addr_string, device)
                    update_attack_log()
                #else:
                    #print("[*] Already attacked {} - Skipping...".format(addr_string))

    except KeyboardInterrupt:
        print('[-] Quitting' + W)
    
    with open('jhackit.out', 'w') as f:
        f.write(json.dumps(jack.devices, cls=ComplexEncoder, skipkeys=True, sort_keys=True, indent=4))
    
    update_attack_log()

    pinged_devices = 0
    hidless_devices = 0
    total_devices = len(__attack_log__)
    for addr_string, device in iteritems(__attack_log__):
        if device['attacked']:
            pinged_devices += 1
        if device['no_hid']:
            hidless_devices += 1

    print("Pinged Devices:  {}".format(pinged_devices))
    print("Hidless Devices: {}".format(hidless_devices))
    print("Total Devices:   {}".format(total_devices))
    #print(json.dumps(__attack_log__, cls=ComplexEncoder, sort_keys=True, indent=4))


if __name__ == '__main__':
    cli()
