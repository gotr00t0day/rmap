import nmap
from colorama import Fore
from utils import exec_cmd, exec_cmd_bash, hex_uuid
import argparse
import os
import xmltodict
import json
import logging
import sys
from libnmap.parser import NmapParser

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


def init():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', type=str, required=True, help="IP Address")

    args = parser.parse_args()
    
    return args


def nmap(host):

    logging.info('Checking/Creating nmap output directory')
    exec_cmd("mkdir -p nmap")

    resultout = f"nmap_{hex_uuid()}"

    cmdnmap = f"nmap -sC -sV {host} -oA nmap/{resultout}"

    logging.info(f'Running...{cmdnmap}')
    exec_cmd(cmdnmap)

    xml_path = f"nmap/{resultout}.xml"

    services_list = parse_nmap_file(xml_path)

    for service in services_list:
        print(service.split(":"))


def ffuf_dir_enum(host, port):
    exec_cmd("mkdir -p ffuf")
    resultout = f"ffuf_{hex_uuid()}"
    cmdffuf = f"ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ffuf/{resultout}.md -fc 302 -u http://{host}:{port}/FUZZ"

    logging.info(f'Running...{cmdffuf}')
    print(exec_cmd(cmdffuf))


def parse_nmap_file(path_xml):
    nmap_report = NmapParser.parse_fromfile(path_xml)

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address


    services = []

    for serv in host.services:
        services.append(f"{serv.service}:{serv.port}")
    
    
    for service in services:
        print(service)
        service = service.split(":")
        if service[0] == "http":
            ffuf_dir_enum("10.129.15.31",service[1])

    return services


def main():
    args = init()
    cwd = os.getcwd()
    global input_cwd
    input_cwd = input(f"Use {cwd} as working directory? (yes or no)")

    if input_cwd != "yes":
        input_cwd = input(f"Enter the work directory path. ")
    else:
        input_cwd = cwd
    
    #print(nmap(args.ip))
    parse_nmap_file("nmap/nmap_58ef8adb86194a34b4ecf1f6222598f1.xml")


main()
