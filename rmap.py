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

    ffuf_wordlist = config_object["FFUF"]["wordlist"]

    RMap(args.ip, ffuf_wordlist)
    #parse_nmap_file("nmap/nmap_58ef8adb86194a34b4ecf1f6222598f1.xml")


main()