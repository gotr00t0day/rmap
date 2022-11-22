#!/usr/bin/python

from rmap import __version__
from rmap.nmap import NmapHandler
from rmap.banner import banner
from rmap.utils import check_ping, exec_cmd, is_tool
from configparser import ConfigParser
from colorama import Fore
import urllib.request
import argparse
import subprocess
import os
from pathlib import Path
import sys
import errno
import logging

if sys.version_info.major < 3:
    print("RMap supports only Python3. Rerun application in Python3 environment.")
    exit(0)

if os.geteuid() != 0:
    print("RMap must run as root. Rerun application using sudo.")
    exit(0)

if not is_tool("nmap"):
    print("Must have nmap installed.")
    exit(0)

if not is_tool("ffuf"):
    print("Must have ffuf installed.")
    exit(0)

if not is_tool("smbclient"):
    print("Must have smbclient installed.")
    exit(0)

def init():
    parser = argparse.ArgumentParser()

    #parser.add_argument('', '--ip', type=str, required=True, help="IP Address")
    parser.add_argument('ip', help="Target IP Address", type=str)
    parser.add_argument('--vuln', default=False, help="Scan host for vulnerabilities", action="store_true")
    parser.add_argument('-d', '--debug', default=False, help="Debug output", action="store_true")
    parser.add_argument('-v', '--version', help="Show version", action='version', version=__version__)

    args = parser.parse_args()
    
    return args

def main():
    args = init()
    banner()
    
    if not check_ping(args.ip):
        logging.error("Did not pass ping check.")
        sys.exit()
    
    exec_cmd("mkdir -p /usr/share/rmap")
    path = Path("/usr/share/rmap/rmap.conf")

    if not path.is_file():
        urllib.request.urlretrieve("https://raw.githubusercontent.com/syspuke/rmap/dev/rmap.conf", "/usr/share/rmap/rmap.conf")
    
    try:
        # Config parser
        config_object = ConfigParser()

        config_object.read("/usr/share/rmap/rmap.conf")

        processes_limit = config_object["rmap"]["processLimit"]
        nmap_all_ports = config_object["nmap"]["allports"]
        nmap_arguments = config_object["nmap"]["arguments"]
        ffuf_wordlist = config_object["ffuf"]["wordlist"]
        ffuf_outtype = config_object["ffuf"]["outtype"]
        ffuf_recursion = config_object["ffuf"]["recursion"]
        ffuf_depth = config_object["ffuf"]["recursionDepth"]
        ffuf_arguments = config_object["ffuf"]["arguments"]

        if nmap_all_ports == "false":
            nmap_all_ports = False
        else:
            nmap_all_ports = True
        if ffuf_recursion == "false":
            ffuf_recursion = False
        else:
            ffuf_recursion = True
    except (IOError, KeyError) as err:
        logging.error(f"Config error: {err}. Using default values.")
        processes_limit = 2
        nmap_all_ports = False
        nmap_arguments = "-sC -sV"
        ffuf_wordlist = "/usr/share/seclists/Discovery/Web-Content/big.txt"
        ffuf_outtype = "md"
        ffuf_recursion = True
        ffuf_depth = 1
        ffuf_arguments = "-fc 302"
    
    try:
        NmapHandler(args.ip, args.debug, int(processes_limit), nmap_all_ports, nmap_arguments, args.vuln, ffuf_wordlist, ffuf_outtype, ffuf_recursion, ffuf_depth, ffuf_arguments)
    except KeyboardInterrupt:
        print(Fore.RED + "[*]" + Fore.YELLOW + f' [CTRL + C DETECTED]' + Fore.RED + f' [EXITING] ' + Fore.RESET)
        sys.exit(0)

if __name__ == "__main__":
    main()