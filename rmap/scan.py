from rmap.utils import exec_cmd, exec_cmd_bash, rmap_print_cmd, rmap_print_msg, get_ping_ttl
from colorama import Fore
from pathlib import Path
from time import sleep
import logging
import multiprocessing
import pexpect

logging.basicConfig(level=logging.DEBUG)
semaphore = multiprocessing.Semaphore(2)

class RMap:
    def __init__(self, host, debug, processes_limit, all_ports, arguments, vulnscan, ffuf_wordlist, ffuf_outtype, ffuf_recursion, ffuf_depth, ffuf_arguments):
        self.host = host
        self.ffuf_wordlist = ffuf_wordlist
        self.ffuf_outtype = ffuf_outtype
        self.all_ports = all_ports
        self.arguments = arguments
        self.vulnscan = vulnscan
        self.debug = debug
        self.processes_limit = processes_limit
        self.ffuf_recursion = ffuf_recursion
        self.ffuf_depth = ffuf_depth
        self.ffuf_arguments = ffuf_arguments


        if self.vulnscan:
            self.vulnscan()
        else:
            self.nmap()


    def vulnscan(self):

        exec_cmd(f"mkdir -p vulnscan")
        path = Path("/usr/share/nmap/scripts/vulscan")
        if not path.is_dir():
            vulscancmd = "git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan"
            rmap_print_msg("Nmap Vulnerability Scan", "Nmap Vulscan Install", vulscancmd)
            exec_cmd_bash(f"{vulscancmd} > /dev/null 2>&1")

        resultout2 = f"vulscan_{self.host}"
        nmapcmd = f'nmap -sV --script=vulscan/vulscan.nse -oN vulnscan/{resultout2} {self.host}'
        rmap_print_msg("Nmap Vulscan Vulnerability Scan", "EXEC", nmapcmd)
        exec_cmd(nmapcmd)

    def nmap(self):
        exec_cmd(f"mkdir -p nmap")

        resultout = f"{self.host}"

        if self.all_ports:
            cmdnmap = f"nmap {self.arguments} -p- -oA nmap/{resultout} {self.host}"
        else:
            cmdnmap = f"nmap {self.arguments} -oA nmap/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.MAGENTA + f' [EXEC] ' + Fore.RESET + Fore.BLUE + cmdnmap + Fore.RESET)
        exec_cmd(cmdnmap)

        xml_path = f"nmap/{resultout}.xml"

        services = self.parse_file(xml_path)
        self.analyse_nmap(services)


    def ffuf_dir_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p ffuf")
        resultout = f"ffuf_{self.host}:{port}"
        if self.ffuf_recursion:
            cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o ffuf/{resultout}.{self.ffuf_outtype} -of {self.ffuf_outtype} -debug-log ffuf/{resultout}.log -recursion {self.ffuf_recursion} -recursion-depth {self.ffuf_depth} {self.ffuf_arguments}"
        else:
            cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o ffuf/{resultout}.{self.ffuf_outtype}  -of {self.ffuf_outtype} -debug-log ffuf/{resultout}.log {self.ffuf_arguments}"
        rmap_print_cmd("HTTP", port, cmdffuf)
        exec_cmd(cmdffuf)
        if self.debug:
            logging.debug(f'[HTTP ENDED] {cmdffuf}')

    def nfs_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p nfs")

        resultout = f"nfs_{self.host}:{port}"
        cmdnmap = f"nmap --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p {port} -oN nfs/{resultout} {self.host}"

        rmap_print_cmd("NFS", port, cmdnmap)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[NFS ENDED] {cmdnmap}')        


    def smb_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p smb")

        resultout = f"smb_{self.host}:{port}"
        cmdnmap = f"nmap --script \"safe or smb-enum-*\" -p {port} -oN smb/{resultout} {self.host}"

        rmap_print_cmd("SMB", port, cmdnmap)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[SMB NMAP ENDED] {cmdnmap}')
        
        resultout2 = f"smbclient_shares_{self.host}:{port}"
        smbclientcmd = f'''smbclient -N -L \\\\{self.host}'''
        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMB Shares]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + smbclientcmd + Fore.RESET)
        exec_cmd_bash(f"{cmdnmap} > smb/{resultout2}")
        if self.debug:
            logging.debug(f'[SMB Shares ENDED] {cmdnmap}')

        resultout3 = f"smb_vuln_{self.host}:{port}"
        cmdnmap2 = f"nmap --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -p {port} -oN smb/{resultout3} {self.host}"
    
        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [SMB Vulnerability Check]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmdnmap2 + Fore.RESET)
        exec_cmd(cmdnmap2)
        if self.debug:
            logging.debug(f'[SMB Vulnerability Check ENDED] {cmdnmap2}')
        

    def samba_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p smb")

        resultout = f"samba_{self.host}:{port}"
        cmdnmap = f"nmap --script=samba-vuln-cve-2012-1182 -p {port} -oN smb/{resultout} {self.host}"

        rmap_print_cmd("Samba", port, cmdnmap)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[Samba NMAP ENDED] {cmdnmap}')


    def ftp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p ftp")
        resultout = f"ftp_{self.host}:{port}"
        cmdnmap = f"nmap --script ftp-* -p {port} -oN ftp/{resultout} {self.host}"

        rmap_print_cmd("FTP", port, cmdnmap)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[FTP ENDED] {cmdnmap}')


    def telnet_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p telnet")
        resultout = f"telnet_{self.host}:{port}"
        telnetnmap = f"nmap -n -sV -Pn --script \"*telnet* and safe\" -p {port} -oN telnet/{resultout} {self.host}"

        rmap_print_cmd("TELNET", port, telnetnmap)
        exec_cmd(telnetnmap)
        if self.debug:
            logging.debug(f'[TELNET ENDED] {telnetnmap}')

    def smtp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p smtp")
        resultout = f"smtp_{self.host}:{port}"
        smtpnmap = f"nmap --script smtp-commands,smtp-open-relay -p {port} -oN smtp/{resultout} {self.host}"

        rmap_print_cmd("SMTP", port, smtpnmap)
        exec_cmd(smtpnmap)
        if self.debug:
            logging.debug(f'[SMTP ENDED] {smtpnmap}')

    def irc_enum(self, port):
        with semaphore:
            sleep(1)
        
        exec_cmd(f"mkdir -p irc")
        resultout = f"irc_{self.host}:{port}"
        ircnmap = f"nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p {port} -oN irc/{resultout} {self.host}"

        rmap_print_cmd("IRC", port, ircnmap)
        exec_cmd(ircnmap)
        if self.debug:
            logging.debug(f'[IRC ENDED] {ircnmap}')

    def javarmi_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p javarmi")        
        resultout = f"javarmi_{self.host}:{port}"
        javarminmap = f"nmap -Pn -sV --script rmi-dumpregistry -p {port} -oN javarmi/{resultout} {self.host}"

        rmap_print_cmd("Java RMI", port, javarminmap)
        exec_cmd(javarminmap)
        if self.debug:
            logging.debug(f'[Java RMI ENDED] {javarminmap}')

    def ldap_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p ldap")
        resultout = f"ldap_{self.host}:{port}"
        ldapnmap = f"nmap -n -sV --script \"ldap* and not brute\" -p {port} -oN ldap/{resultout} {self.host}"

        rmap_print_cmd("LDAP", port, ldapnmap)
        exec_cmd(ldapnmap)

        if self.debug:
            logging.debug(f'[LDAP ENDED] {ldapnmap}')              

    def mysql_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p mysql")
        resultout = f"mysql_{self.host}:{port}"
        mysqlnmap = f"nmap -sV --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p {port} -oN mysql/{resultout} {self.host}"

        rmap_print_cmd("MYSQL", port, mysqlnmap)
        exec_cmd(mysqlnmap)

        if self.debug:
            logging.debug(f'[MYSQL ENDED] {mysqlnmap}')

    def rdp_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p rdp")
        resultout = f"rdp_{self.host}:{port}"
        rdpnmap = f"nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p {port} -oN rdp/{resultout} {self.host}"

        rmap_print_cmd("RDP", port, rdpnmap)
        exec_cmd(rdpnmap)

        if self.debug:
            logging.debug(f'[RDP ENDED] {rdpnmap}')

    def redis_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p redis")
        resultout = f"redis_{self.host}:{port}"
        redisnmap = f"nmap --script redis-info -sV -p {port} -oN redis/{resultout} {self.host}"

        rmap_print_cmd("Redis", port, redisnmap)
        exec_cmd(redisnmap)

        if self.debug:
            logging.debug(f'[REDIS ENDED] {redisnmap}')
    
    def ajp13_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p ajp13")
        resultout = f"ajp13_{self.host}:{port}"
        ajp13nmap = f"nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p {port} -oN ajp13/{resultout} {self.host}"

        rmap_print_cmd("Apache JServ", port, ajp13nmap)
        exec_cmd(ajp13nmap)

        if self.debug:
            logging.debug(f'[Apache JServ ENDED] {ajp13nmap}')                

    def couchdb_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p couchdb")
        resultout = f"couchdb_{self.host}:{port}"
        couchdbnmap = f"nmap -sV --script couchdb-databases,couchdb-stats -p {port} -oN couchdb/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [CouchDB DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + couchdbnmap + Fore.RESET)
        rmap_print_cmd("CouchDB", port, couchdbnmap)
        exec_cmd(couchdbnmap)

        if self.debug:
            logging.debug(f'[CouchDB ENDED] {couchdbnmap}')        

    def bitcoin_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p bitcoin")
        resultout = f"bitcoin_{self.host}:{port}"
        btcnmap = f"nmap -sV --script bitcoin-info --script bitcoin-getaddr -p {port} -oN bitcoin/{resultout} {self.host}"

        rmap_print_cmd("Bitcoin", port, btcnmap)
        exec_cmd(btcnmap)

        if self.debug:
            logging.debug(f'[Bitcoin ENDED] {btcnmap}')        


    def cassandra_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p cassandra")
        resultout = f"cassandra_{self.host}:{port}"
        cassandranmap = f"nmap -sV --script cassandra-info -p {port} -oN cassandra/{resultout} {self.host}"

        rmap_print_cmd("Cassandra", port, cassandranmap)
        exec_cmd(cassandranmap)

        if self.debug:
            logging.debug(f'[Cassandra ENDED] {cassandranmap}')        


    def mongodb_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p mongodb")
        resultout = f"mongodb_{self.host}:{port}"
        mongodbnmap = f"nmap -sV --script \"mongo* and default\" -p {port} -oN mongodb/{resultout} {self.host}"

        rmap_print_cmd("MongoDB", port, mongodbnmap)
        exec_cmd(mongodbnmap)

        if self.debug:
            logging.debug(f'[MongoDB ENDED] {mongodbnmap}')

    def pop3_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p pop3")
        resultout = f"pop3_{self.host}:{port}"
        pop3nmap = f"nmap -sV --script \"pop3-capabilities or pop3-ntlm-info\" -p {port} -oN pop3/{resultout} {self.host}"

        rmap_print_cmd("POP3", port, pop3nmap)
        exec_cmd(pop3nmap)

    def amqp_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p amqp")
        resultout = f"amqp_{self.host}:{port}"
        amqpnmap = f"nmap -sV --script amqp-info -p {port} -oN amqp/{resultout} {self.host}"

        rmap_print_cmd("RabbitMQ", port, amqpnmap)
        exec_cmd(amqpnmap)