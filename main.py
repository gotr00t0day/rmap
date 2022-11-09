import nmap
from colorama import Fore
from utils import exec_cmd, exec_cmd_bash, hex_uuid
import argparse
import os
import xmltodict
import json

def init():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")

    args = parser.parse_args()
    
    return args


def nmap(host):

    exec_cmd("mkdir -p nmap")

    resultout = f"nmap_{hex_uuid()}"

    exec_cmd(f"nmap -sC -sV {host} -oA nmap/{resultout}")
    with open("nmap/" + resultout + ".xml") as f:
        xml = f.read()
        d = json.loads(json.dumps(xmltodict.parse(xml)))

        print(d)



def main():
    args = init()
    cwd = os.getcwd()
    global input_cwd
    input_cwd = input(f"Use {cwd} as working directory? (yes or no)")

    if input_cwd != "yes":
        input_cwd = input(f"Enter the work directory path. ")
    else:
        input_cwd = cwd
    
    print(nmap(args.ip))

main()
