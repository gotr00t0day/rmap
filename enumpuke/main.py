import nmap
from colorama import Fore
from enumpuke.utils import exec_cmd, exec_cmd_bash, hex_uuid, check_ping
import os
import xmltodict
import json
import logging
import sys
from libnmap.parser import NmapParser

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


def nmap(host):

    logging.info('Checking/Creating nmap output directory')
    exec_cmd("mkdir -p nmap")

    resultout = f"nmap_{hex_uuid()}"

    cmdnmap = f"nmap -sC -sV -oA nmap/{resultout} {host}"

    logging.info(f'Running...{cmdnmap}')
    exec_cmd(cmdnmap)

    xml_path = f"nmap/{resultout}.xml"

    services_list = parse_nmap_file(xml_path)


def ffuf_dir_enum(host, port):
    print(ffuf_wordlist)
    exec_cmd("mkdir -p ffuf")
    resultout = f"ffuf_{hex_uuid()}"
    cmdffuf = f"ffuf -w {ffuf_wordlist} -u http://{host}:{port}/FUZZ -o ffuf/{resultout}.md -fc 302"
    logging.info(f'[HTTP DETECTED] Running...{cmdffuf}')
    print(exec_cmd(cmdffuf))

def nmap_smb_enum(host, port):
    exec_cmd("mkdir -p nmap")
    resultout = f"smb_{hex_uuid()}"
    cmdnmap = f"nmap --script=smb-enum-shares.nse,smb-enum-users.nse -p {port} -oA nmap/{resultout} {host}"

    logging.info(f'[SMB DETECTED] Running...{cmdnmap}')
    print(exec_cmd(cmdnmap))

def parse_nmap_file(path_xml):
    nmap_report = NmapParser.parse_fromfile(path_xml)

    services = []

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        for serv in host.services:
            services.append(f"{serv.service}:{serv.port}")
    
    
    for service in services:
        service = service.split(":")
        if service[0] == "http":
            ffuf_dir_enum(host.address,service[1])
        elif service[0] == "microsoft-ds":
            nmap_smb_enum(host.address,service[1])


    return services

