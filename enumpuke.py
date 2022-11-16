
from enumpuke.main import nmap
from enumpuke.banner import banner
from enumpuke.utils import check_ping
import argparse
import os
from configparser import ConfigParser

ffuf_wordlist = ""

def init():
    config_object = ConfigParser()
    config_object.read("config.ini")

    ffuf_wordlist = config_object["FFUF"]["wordlist"]

    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")
    parser.add_argument('--cwd', type=str, help="Working Directory")
    parser.add_argument('--wl', type=str, help="Wordlist")

    args = parser.parse_args()
    
    return args


def main():
    args = init()
    cwd = os.getcwd()
    banner()
    
    if not check_ping(args.ip):
        logging.error("Did not pass ping check.")
        sys.exit()

    nmap(args.ip)
    #parse_nmap_file("nmap/nmap_58ef8adb86194a34b4ecf1f6222598f1.xml")


main()