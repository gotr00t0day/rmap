import nmap
from colorama import Fore
from rmap.utils import exec_cmd, exec_cmd_bash, hex_uuid, check_ping
import os
import xmltodict
import json
import logging
import requests
import sys
import socket
from time import sleep
from random import randint
from libnmap.parser import NmapParser
import multiprocessing

logging.basicConfig(level=logging.DEBUG)
semaphore = multiprocessing.Semaphore(2)

class RMap:
    def __init__(self, host, debug, processes_limit, nmap_all_ports, nmap_arguments, ffuf_wordlist, ffuf_outtype):
        self.host = host
        self.os = ""
        self.ffuf_wordlist = ffuf_wordlist
        self.ffuf_outtype = ffuf_outtype
        self.services = []
        self.nmap_all_ports = nmap_all_ports
        self.nmap_arguments = nmap_arguments
        self.debug = debug
        self.processes_limit = processes_limit

        self.nmap()
        
    def nmap(self):
        exec_cmd("mkdir -p nmap")

        resultout = f"nmap_{self.host}"

        if self.nmap_all_ports:
            cmdnmap = f"nmap {self.nmap_arguments} -p- -oA nmap/{resultout} {self.host}"
        else:
            cmdnmap = f"nmap {self.nmap_arguments} -oA nmap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.MAGENTA + f' [EXEC] ' + Fore.RESET + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)

        xml_path = f"nmap/{resultout}.xml"

        self.parse_nmap_file(xml_path)
        self.analyse_nmap()


    def ffuf_dir_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p ffuf")
        resultout = f"ffuf_{self.host}:{port}"
        cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o ffuf/{resultout}.{self.ffuf_outtype} -of {self.ffuf_outtype} -fc 302"
        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [HTTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdffuf + Fore.RESET)
        exec_cmd_bash(f"{cmdffuf} > ffuf/{resultout}.txt")
        if self.debug:
            logging.debug(f'[HTTP ENDED] {cmdffuf}')


    def nmap_smb_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p smb")
        resultout = f"smb_{self.host}:{port}"
        cmdnmap = f"nmap --script \"safe or smb-enum-*\" -p {port} -oN smb/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMB DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[SMB ENDED] {cmdnmap}')
    
    def nmap_ftp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p ftp")
        resultout = f"ftp_{self.host}:{port}"
        cmdnmap = f"nmap --script ftp-* -p {port} -oN ftp/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [FTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[FTP ENDED] {cmdnmap}')

    def wordpress_detect(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p wordpress")
        

        try:
            r = requests.get(f"http://{self.host}:{port}", verify=False, timeout=5)
        except:
            pass
        print(r.history)

    def nmap_telnet_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p telnet")
        resultout = f"telnet_{self.host}:{port}"
        telnetnmap = f"nmap -n -sV -Pn --script \"*telnet* and safe\" -p {port} -oN telnet/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [TELNET DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + telnetnmap + Fore.RESET)
        exec_cmd(telnetnmap)
        if self.debug:
            logging.debug(f'[TELNET ENDED] {telnetnmap}')

    def nmap_smtp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd("mkdir -p smtp")
        resultout = f"smtp_{self.host}:{port}"
        smtpnmap = f"nmap --script smtp-commands,smtp-open-relay -p {port} -oN smtp/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + smtpnmap + Fore.RESET)
        exec_cmd(smtpnmap)
        if self.debug:
            logging.debug(f'[SMTP ENDED] {smtpnmap}')

    def nmap_irc_enum(self, port):
        with semaphore:
            sleep(1)
        
        exec_cmd("mkdir -p irc")
        resultout = f"irc_{self.host}:{port}"
        ircnmap = f"nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p {port} -oN irc/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [IRC DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + ircnmap + Fore.RESET)
        exec_cmd(ircnmap)
        if self.debug:
            logging.debug(f'[IRC ENDED] {ircnmap}')

    def nmap_javarmi_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd("mkdir -p javarmi")        
        resultout = f"javarmi_{self.host}:{port}"
        javarminmap = f"nmap -Pn -sV --script rmi-dumpregistry -p {port} -oN javarmi/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [Java RMI DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + javarminmap + Fore.RESET)
        exec_cmd(javarminmap)
        if self.debug:
            logging.debug(f'[Java RMI ENDED] {javarminmap}')

    def nmap_ldap_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd("mkdir -p ldap")
        resultout = f"ldap_{self.host}:{port}"
        ldapnmap = f"nmap -n -sV --script \"ldap* and not brute\" -p {port} -oN ldap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [LDAP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + ldapnmap + Fore.RESET)
        exec_cmd(ldapnmap)

        if self.debug:
            logging.debug(f'[LDAP ENDED] {ldapnmap}')              

    def nmap_mysql_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd("mkdir -p mysql")
        resultout = f"mysql_{self.host}:{port}"
        mysqlnmap = f"nmap -sV --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p {port} -oN mysql/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [MYSQL DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + mysqlnmap + Fore.RESET)
        exec_cmd(mysqlnmap)

        if self.debug:
            logging.debug(f'[MYSQL ENDED] {mysqlnmap}')              


    def parse_nmap_file(self, path_xml):
        nmap_report = NmapParser.parse_fromfile(path_xml)

        services = []

        for host in nmap_report.hosts:
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address
            
            for osm in host.os.osmatches:
                print(f"Found Match:{osm.name} ({osm.accuracy}%)")

            for serv in host.services:
                # Collect nmap results into a list
                services.append(f"{serv.service}:{serv.port}")


        self.services = services

    def analyse_nmap(self):
        with multiprocessing.Pool(processes=int(self.processes_limit)) as pool:
            for service in self.services:
                service = service.split(":")
                if service[0] == "ftp":
                    pool.apply_async(self.nmap_ftp_enum, [service[1]])
                if service[0] == "telnet":
                    pool.apply_async(self.nmap_telnet_enum, [service[1]])
                if service[0] == "http":
                    pool.apply_async(self.ffuf_dir_enum, [service[1]])
                    sleep(3)
                    pool.apply_async(self.wordpress_detect, [service[1]])
                if service[0] == "smtp":
                    pool.apply_async(self.nmap_smtp_enum, [service[1]])
                if service[0] == "irc":
                    pool.apply_async(self.nmap_irc_enum, [service[1]])
                if service[0] == "ldap":
                    pool.apply_async(self.nmap_ldap_enum, [service[1]])
                if service[0] == "mysql":
                    pool.apply_async(self.nmap_mysql_enum, [service[1]])
                if service[0] == "java-rmi":
                    pool.apply_async(self.nmap_javarmi_enum, [service[1]])
                if int(service[1]) == 445:
                    pool.apply_async(self.nmap_smb_enum, [service[1]])

            pool.close()
            pool.join()
