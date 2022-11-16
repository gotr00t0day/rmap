import nmap
from colorama import Fore
from rmap.utils import exec_cmd, exec_cmd_bash, hex_uuid, check_ping
import os
import xmltodict
import json
import logging
import sys
from libnmap.parser import NmapParser

class RMap:
    def __init__(self, host, ffuf_wordlist):
        self.host = host
        self.ffuf_wordlist = ffuf_wordlist
        self.services = []

        self.nmap()
        
    def nmap(self):
        exec_cmd("mkdir -p nmap")

        resultout = f"nmap_{self.host}"

        cmdnmap = f"nmap -sC -sV -oA nmap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.BLUE + f' Running...{cmdnmap}' + Fore.RESET)
        exec_cmd(cmdnmap)

        xml_path = f"nmap/{resultout}.xml"

        self.parse_nmap_file(xml_path)
        self.analyse_nmap()


    def ffuf_dir_enum(self, port):
        exec_cmd("mkdir -p ffuf")
        resultout = f"ffuf_{self.host}:{port}"
        cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o ffuf/{resultout}.md -fc 302"
        print(Fore.RED + "[*]" + Fore.GREEN + f' [HTTP DETECTED] [{self.host}:{port}] Running...{cmdffuf}' + Fore.RESET)
        exec_cmd(cmdffuf)


    def nmap_smb_enum(self, port):
        exec_cmd("mkdir -p nmap")
        resultout = f"smb_{self.host}:{port}"
        cmdnmap = f"nmap --script=smb-enum-shares.nse,smb-enum-users.nse -p {port} -oA nmap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [SMB DETECTED] [{self.host}:{port}] Running...{cmdnmap}' + Fore.RESET)
        exec_cmd(cmdnmap)


    def parse_nmap_file(self, path_xml):
        nmap_report = NmapParser.parse_fromfile(path_xml)

        services = []

        for host in nmap_report.hosts:
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address

            for serv in host.services:
                services.append(f"{serv.service}:{serv.port}")

        self.services = services

    def analyse_nmap(self):
        for service in self.services:
            service = service.split(":")
            if service[0] == "http":
                self.ffuf_dir_enum(service[1])
            elif service[0] == "microsoft-ds":
                self.nmap_smb_enum(service[1])
