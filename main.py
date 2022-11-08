import nmap
from colorama import Fore
from utils import exec_cmd, exec_cmd_bash
import argparse
import os

def init():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")

    args = parser.parse_args()
    
    return args


def nmap(host):
    return exec_cmd(f"nmap -sC -sV {host}")


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
