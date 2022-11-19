#!/usr/bin/python

from rmap.main import RMap
from rmap.banner import banner
from rmap.utils import check_ping, exec_cmd
from configparser import ConfigParser
import argparse
import subprocess
import os
from pathlib import Path
import sys

def is_tool(name):
    try:
        devnull = open(os.devnull)
        subprocess.Popen([name], stdout=devnull, stderr=devnull).communicate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
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
    cwd = os.getcwd()
    banner()
    
    if not check_ping(args.ip):
        logging.error("Did not pass ping check.")
        sys.exit()
    
    exec_cmd("mkdir -p /usr/share/rmap")
    path = Path("/usr/share/rmap/rmap.conf")

    if not path.is_file():
        exec_cmd("curl https://raw.githubusercontent.com/syspuke/rmap/main/rmap.conf -o /usr/share/rmap/rmap.conf -s")
    
    # Config parser
    config_object = ConfigParser()

    config_object.read("/usr/share/rmap/rmap.conf")

    processes_limit = config_object["rmap"]["processLimit"]
    nmap_all_ports = config_object["nmap"]["allports"]
    nmap_arguments = config_object["nmap"]["arguments"]
    ffuf_wordlist = config_object["ffuf"]["wordlist"]
    ffuf_outtype = config_object["ffuf"]["outtype"]

    if nmap_all_ports == "false":
        nmap_all_ports = False

    RMap(args.ip, args.d, int(processes_limit), nmap_all_ports, nmap_arguments, ffuf_wordlist, ffuf_outtype)

if __name__ == "__main__":
    main()