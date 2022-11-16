from rmap.main import RMap
from rmap.banner import banner
from rmap.utils import check_ping
from configparser import ConfigParser
import argparse
import os
import sys

if sys.version_info.major < 3:
    print("RMap supports only Python3. Rerun application in Python3 environment.")
    exit(0)

def init():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")
    parser.add_argument('--cwd', type=str, help="Working Directory")

    args = parser.parse_args()
    
    return args


def main():
    args = init()
    cwd = os.getcwd()
    banner()
    
    if not check_ping(args.ip):
        logging.error("Did not pass ping check.")
        sys.exit()
    
    # Config parser
    config_object = ConfigParser()
    config_object.read("rmap.conf")

    nmap_all_ports = config_object["nmap"]["allports"]
    ffuf_wordlist = config_object["ffuf"]["wordlist"]
    ffuf_outtype = config_object["ffuf"]["outtype"]

    if nmap_all_ports == "false":
        nmap_all_ports = False

    RMap(args.ip, nmap_all_ports, ffuf_wordlist, ffuf_outtype)


main()