#!/usr/bin/python

from rmap.nmap import NmapHandler
from rmap.banner import banner
from rmap.utils import check_ping, exec_cmd
from configparser import ConfigParser
import urllib.request
import argparse
import subprocess
import os
from pathlib import Path
import sys
import errno
import logging

def is_tool(name):
    try:
        devnull = open(os.devnull)
        subprocess.Popen([name], stdout=devnull, stderr=devnull).communicate()
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
    return True

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

def init():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")
    parser.add_argument('-d', default=False, help="Debug output", action="store_true")

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
        urllib.request.urlretrieve("https://raw.githubusercontent.com/syspuke/rmap/main/rmap.conf", "/usr/share/rmap/rmap.conf")
    
    try:
        # Config parser
        config_object = ConfigParser()

        config_object.read("/usr/share/rmap/rmap.conf")

        processes_limit = config_object["rmap"]["processLimit"]
        pre_os_check = config_object["nmap"]["OSCheck"]
        nmap_all_ports = config_object["nmap"]["allports"]
        nmap_arguments = config_object["nmap"]["arguments"]
        nmap_vulnscan = config_object["nmap"]["vulnScan"]
        ffuf_wordlist = config_object["ffuf"]["wordlist"]
        ffuf_outtype = config_object["ffuf"]["outtype"]

        if nmap_all_ports == "false":
            nmap_all_ports = False
        else:
            nmap_all_ports = True
        if pre_os_check == "false":
            pre_os_check = False
        else:
            pre_os_check = True
        if nmap_vulnscan == "false":
            nmap_vulnscan = False
        else:
            nmap_vulnscan = True
    except (IOError, KeyError):
        logging.error("Config error. Using default values.")
        processes_limit = 2
        pre_os_check = True
        nmap_all_ports = False
        nmap_arguments = "-sC -sV"
        nmap_vulnscan = False
        ffuf_wordlist = "/usr/share/seclists/Discovery/Web-Content/big.txt"
        ffuf_outtype = "md"


    NmapHandler(args.ip, args.d, int(processes_limit), nmap_all_ports, pre_os_check, nmap_arguments, nmap_vulnscan, ffuf_wordlist, ffuf_outtype)

if __name__ == "__main__":
    main()