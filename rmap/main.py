from colorama import Fore
from rmap.utils import exec_cmd, exec_cmd_bash
import logging
from time import sleep
from libnmap.parser import NmapParser
import multiprocessing

logging.basicConfig(level=logging.DEBUG)
semaphore = multiprocessing.Semaphore(2)

outdir = "rmap-report"

class RMap:
    def __init__(self, host, debug, processes_limit, nmap_all_ports, nmap_arguments, ffuf_wordlist, ffuf_outtype):
        self.host = host
        self.ffuf_wordlist = ffuf_wordlist
        self.ffuf_outtype = ffuf_outtype
        self.services = []
        self.nmap_all_ports = nmap_all_ports
        self.nmap_arguments = nmap_arguments
        self.debug = debug
        self.processes_limit = processes_limit

        exec_cmd(f"mkdir -p {outdir}")
        self.nmap()
        
    def nmap(self):
        exec_cmd(f"mkdir -p {outdir}/nmap")

        resultout = f"nmap_{self.host}"

        if self.nmap_all_ports:
            cmdnmap = f"nmap {self.nmap_arguments} -p- -oA {outdir}/nmap/{resultout} {self.host}"
        else:
            cmdnmap = f"nmap {self.nmap_arguments} -oA {outdir}/nmap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.MAGENTA + f' [EXEC] ' + Fore.RESET + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)

        xml_path = f"{outdir}/nmap/{resultout}.xml"

        self.parse_nmap_file(xml_path)
        self.analyse_nmap()


    def ffuf_dir_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/ffuf")
        resultout = f"ffuf_{self.host}:{port}"
        cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o {outdir}/ffuf/{resultout}.{self.ffuf_outtype} -of {self.ffuf_outtype} -fc 302"
        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [HTTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdffuf + Fore.RESET)
        exec_cmd_bash(f"{cmdffuf} > {outdir}/ffuf/{resultout}.txt")
        if self.debug:
            logging.debug(f'[HTTP ENDED] {cmdffuf}')


    def nmap_smb_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/smb")
        resultout = f"smb_{self.host}:{port}"
        cmdnmap = f"nmap --script \"safe or smb-enum-*\" -p {port} -oN {outdir}/smb/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMB DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[SMB ENDED] {cmdnmap}')
        
        resultout2 = f"smb_vuln_{self.host}:{port}"
        cmdnmap2 = f"nmap --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -p {port} -oN {outdir}/smb/{resultout2} {self.host}"
    
        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMB Vulnerability Check]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap2 + Fore.RESET)
        exec_cmd(cmdnmap2)
        if self.debug:
            logging.debug(f'[SMB ENDED] {cmdnmap2}')

    def nmap_ftp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/ftp")
        resultout = f"ftp_{self.host}:{port}"
        cmdnmap = f"nmap --script ftp-* -p {port} -oN {outdir}/ftp/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [FTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[FTP ENDED] {cmdnmap}')


    def nmap_telnet_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/telnet")
        resultout = f"telnet_{self.host}:{port}"
        telnetnmap = f"nmap -n -sV -Pn --script \"*telnet* and safe\" -p {port} -oN {outdir}/telnet/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [TELNET DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + telnetnmap + Fore.RESET)
        exec_cmd(telnetnmap)
        if self.debug:
            logging.debug(f'[TELNET ENDED] {telnetnmap}')

    def nmap_smtp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/smtp")
        resultout = f"smtp_{self.host}:{port}"
        smtpnmap = f"nmap --script smtp-commands,smtp-open-relay -p {port} -oN {outdir}/smtp/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMTP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + smtpnmap + Fore.RESET)
        exec_cmd(smtpnmap)
        if self.debug:
            logging.debug(f'[SMTP ENDED] {smtpnmap}')

    def nmap_irc_enum(self, port):
        with semaphore:
            sleep(1)
        
        exec_cmd(f"mkdir -p {outdir}/irc")
        resultout = f"irc_{self.host}:{port}"
        ircnmap = f"nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p {port} -oN {outdir}/irc/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [IRC DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + ircnmap + Fore.RESET)
        exec_cmd(ircnmap)
        if self.debug:
            logging.debug(f'[IRC ENDED] {ircnmap}')

    def nmap_javarmi_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/javarmi")        
        resultout = f"javarmi_{self.host}:{port}"
        javarminmap = f"nmap -Pn -sV --script rmi-dumpregistry -p {port} -oN {outdir}/javarmi/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [Java RMI DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + javarminmap + Fore.RESET)
        exec_cmd(javarminmap)
        if self.debug:
            logging.debug(f'[Java RMI ENDED] {javarminmap}')

    def nmap_ldap_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/ldap")
        resultout = f"ldap_{self.host}:{port}"
        ldapnmap = f"nmap -n -sV --script \"ldap* and not brute\" -p {port} -oN {outdir}/ldap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [LDAP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + ldapnmap + Fore.RESET)
        exec_cmd(ldapnmap)

        if self.debug:
            logging.debug(f'[LDAP ENDED] {ldapnmap}')              

    def nmap_mysql_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/mysql")
        resultout = f"mysql_{self.host}:{port}"
        mysqlnmap = f"nmap -sV --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p {port} -oN {outdir}/mysql/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [MYSQL DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + mysqlnmap + Fore.RESET)
        exec_cmd(mysqlnmap)

        if self.debug:
            logging.debug(f'[MYSQL ENDED] {mysqlnmap}')

    def nmap_rdp_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/rdp")
        resultout = f"rdp_{self.host}:{port}"
        rdpnmap = f"nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p {port} -oN {outdir}/rdp/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [RDP DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + rdpnmap + Fore.RESET)
        exec_cmd(rdpnmap)

        if self.debug:
            logging.debug(f'[RDP ENDED] {rdpnmap}')

    def nmap_redis_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/redis")
        resultout = f"redis_{self.host}:{port}"
        redisnmap = f"nmap --script redis-info -sV -p {port} -oN {outdir}/redis/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [REDIS DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + redisnmap + Fore.RESET)
        exec_cmd(redisnmap)

        if self.debug:
            logging.debug(f'[REDIS ENDED] {redisnmap}')
    
    def nmap_ajp13_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/ajp13")
        resultout = f"ajp13_{self.host}:{port}"
        ajp13nmap = f"nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p {port} -oN {outdir}/ajp13/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [Apache JServ DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + ajp13nmap + Fore.RESET)
        exec_cmd(ajp13nmap)

        if self.debug:
            logging.debug(f'[Apache JServ ENDED] {ajp13nmap}')                


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
        with multiprocessing.Pool(processes=int(self.processes_limit)) as pool:
            for service in self.services:
                service = service.split(":")
                if service[0] == "ftp":
                    pool.apply_async(self.nmap_ftp_enum, [service[1]])
                if service[0] == "telnet":
                    pool.apply_async(self.nmap_telnet_enum, [service[1]])
                if service[0] == "http":
                    pool.apply_async(self.ffuf_dir_enum, [service[1]])
                    #sleep(3)
                    #pool.apply_async(self.wordpress_detect, [service[1]])
                if service[0] == "smtp":
                    pool.apply_async(self.nmap_smtp_enum, [service[1]])
                if service[0] == "ms-wbt-server":
                    pool.apply_async(self.nmap_rdp_enum, [service[1]])
                if service[0] == "irc":
                    pool.apply_async(self.nmap_irc_enum, [service[1]])
                if service[0] == "redis":
                    pool.apply_async(self.nmap_redis_enum, [service[1]])
                if service[0] == "ldap":
                    pool.apply_async(self.nmap_ldap_enum, [service[1]])
                if service[0] == "mysql":
                    pool.apply_async(self.nmap_mysql_enum, [service[1]])
                if service[0] == "ajp13":
                    pool.apply_async(self.nmap_ajp13_enum, [service[1]])
                if service[0] == "java-rmi":
                    pool.apply_async(self.nmap_javarmi_enum, [service[1]])
                if int(service[1]) == 445:
                    pool.apply_async(self.nmap_smb_enum, [service[1]])

            pool.close()
            pool.join()
