from rmap.utils import exec_cmd, exec_cmd_bash, rmap_print_cmd, rmap_print_msg, get_ping_ttl
from colorama import Fore
from pathlib import Path
from time import sleep
import logging
import multiprocessing

logging.basicConfig(level=logging.DEBUG)
semaphore = multiprocessing.Semaphore(2)

outdir = "rmap-report"

class RMap:
    def __init__(self, host, debug, processes_limit, nmap_all_ports, pre_os_check, nmap_arguments, vulnscan, ffuf_wordlist, ffuf_outtype, scan_timeout):
        self.host = host
        self.ffuf_wordlist = ffuf_wordlist
        self.ffuf_outtype = ffuf_outtype
        self.nmap_all_ports = nmap_all_ports
        self.nmap_arguments = nmap_arguments
        self.vulnscan = vulnscan
        self.debug = debug
        self.processes_limit = processes_limit
        self.pre_os_check = pre_os_check
        self.scan_timeout = scan_timeout

        self.os_detected = self.os_detect()
            
        if self.os_detected == "Unknown":
            rmap_print_msg("OS DETECTION", "FAILED", "Couldn't detect the target OS.")


        if self.vulnscan:
            self.nmap_vulnscan()
        else:
            exec_cmd(f"mkdir -p {outdir}")
            self.nmap()

    def os_detect(self):

        suspected_os = "Unknown"
        ttl_result = get_ping_ttl(self.host)

        # Linux
        if ttl_result == 64:
            suspected_os = "Linux"
        
        # Windows sometimes varies in this range
        if ttl_result > 120 and ttl_result < 130:
            suspected_os = "Windows"
        
        if self.pre_os_check:
            if suspected_os != "Unknown":
                rmap_print_msg("OS DETECTION", "ICMP TTL", f"Suspected OS: {suspected_os}. Running Nmap OS detection...")
                nmapresult = self.nmap_os_detect()
                if nmapresult != "Unknown":
                    rmap_print_msg("OS DETECTION", "NMAP OS MATCH", nmapresult)
                    return nmapresult
                else:
                    return suspected_os
            else:
                return "Unknown"
        else:
            rmap_print_msg("OS DETECTION", "ICMP TTL", f"Suspected OS: {suspected_os}.")
            return suspected_os
    
    def nmap_os_detect(self):
        awkcmd = ''' awk '{for (I=1;I<NF;I++) if ($I == "CPE:") printf $(I+1)}' '''
        nmapcmd = f'nmap --top-ports 10 -sV -T4 -O {self.host}'
        rmap_print_msg("OS DETECTION", "EXEC", nmapcmd)
        osresult = exec_cmd_bash(f"{nmapcmd} | {awkcmd} | tr -d \;")

        if osresult[1] != 0:
            if self.debug:
                logging.debug(f'[OS DETECTION NMAP FAILED] [RESULT] {osresult}')
            return "Unknown"
        
        if osresult[0] == "":
            if self.debug:
                logging.debug(f'[OS DETECTION NMAP FAILED] [RESULT] {osresult}')
            return "Unknown"

        if self.debug:
            logging.debug(f'[OS DETECTION NMAP ENDED] [RESULT] {osresult}')

        if "windows" in osresult[0]:
            return "Windows"
        elif "linux" in osresult[0]:
            return "Linux"

        return "Unknown"

    def nmap_vulnscan(self):

        exec_cmd(f"mkdir -p {outdir}/vulnscan")
        path = Path("/usr/share/nmap/scripts/vulscan")
        if not path.is_dir():
            vulscancmd = "git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan"
            rmap_print_msg("Nmap Vulnerability Scan", "Nmap Vulscan Install", vulscancmd)
            exec_cmd_bash(f"{vulscancmd} > /dev/null 2>&1")

        resultout2 = f"vulscan_{self.host}"
        nmapcmd = f'nmap -sV --script=vulscan/vulscan.nse -oN {outdir}/vulnscan/{resultout2} {self.host}'
        rmap_print_msg("Nmap Vulscan Vulnerability Scan", "EXEC", nmapcmd)
        exec_cmd(nmapcmd)

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

        services = self.parse_nmap_file(xml_path)
        self.analyse_nmap(services)


    def ffuf_dir_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/ffuf")
        resultout = f"ffuf_{self.host}:{port}"
        cmdffuf = f"ffuf -w {self.ffuf_wordlist} -u http://{self.host}:{port}/FUZZ -o {outdir}/ffuf/{resultout}.{self.ffuf_outtype} -of {self.ffuf_outtype} -fc 302"
        rmap_print_cmd("HTTP", port, cmdffuf)
        exec_cmd_bash(f"{cmdffuf} > {outdir}/ffuf/{resultout}.txt")
        if self.debug:
            logging.debug(f'[HTTP ENDED] {cmdffuf}')


    def nmap_smb_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/smb")
        resultout = f"smb_{self.host}:{port}"
        cmdnmap = f"nmap --script \"safe or smb-enum-*\" -p {port} -oN {outdir}/smb/{resultout} {self.host}"

        rmap_print_cmd("SMB", port, cmdnmap)
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

        rmap_print_cmd("FTP", port, cmdnmap)
        exec_cmd(cmdnmap)
        if self.debug:
            logging.debug(f'[FTP ENDED] {cmdnmap}')


    def nmap_telnet_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/telnet")
        resultout = f"telnet_{self.host}:{port}"
        telnetnmap = f"nmap -n -sV -Pn --script \"*telnet* and safe\" -p {port} -oN {outdir}/telnet/{resultout} {self.host}"

        rmap_print_cmd("TELNET", port, telnetnmap)
        exec_cmd(telnetnmap)
        if self.debug:
            logging.debug(f'[TELNET ENDED] {telnetnmap}')

    def nmap_smtp_enum(self, port):
        with semaphore:
            sleep(1)
        exec_cmd(f"mkdir -p {outdir}/smtp")
        resultout = f"smtp_{self.host}:{port}"
        smtpnmap = f"nmap --script smtp-commands,smtp-open-relay -p {port} -oN {outdir}/smtp/{resultout} {self.host}"

        rmap_print_cmd("SMTP", port, smtpnmap)
        exec_cmd(smtpnmap)
        if self.debug:
            logging.debug(f'[SMTP ENDED] {smtpnmap}')

    def nmap_irc_enum(self, port):
        with semaphore:
            sleep(1)
        
        exec_cmd(f"mkdir -p {outdir}/irc")
        resultout = f"irc_{self.host}:{port}"
        ircnmap = f"nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p {port} -oN {outdir}/irc/{resultout} {self.host}"

        rmap_print_cmd("IRC", port, ircnmap)
        exec_cmd(ircnmap)
        if self.debug:
            logging.debug(f'[IRC ENDED] {ircnmap}')

    def nmap_javarmi_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/javarmi")        
        resultout = f"javarmi_{self.host}:{port}"
        javarminmap = f"nmap -Pn -sV --script rmi-dumpregistry -p {port} -oN {outdir}/javarmi/{resultout} {self.host}"

        rmap_print_cmd("Java RMI", port, javarminmap)
        exec_cmd(javarminmap)
        if self.debug:
            logging.debug(f'[Java RMI ENDED] {javarminmap}')

    def nmap_ldap_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/ldap")
        resultout = f"ldap_{self.host}:{port}"
        ldapnmap = f"nmap -n -sV --script \"ldap* and not brute\" -p {port} -oN {outdir}/ldap/{resultout} {self.host}"

        rmap_print_cmd("LDAP", port, ldapnmap)
        exec_cmd(ldapnmap)

        if self.debug:
            logging.debug(f'[LDAP ENDED] {ldapnmap}')              

    def nmap_mysql_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/mysql")
        resultout = f"mysql_{self.host}:{port}"
        mysqlnmap = f"nmap -sV --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p {port} -oN {outdir}/mysql/{resultout} {self.host}"

        rmap_print_cmd("MYSQL", port, mysqlnmap)
        exec_cmd(mysqlnmap)

        if self.debug:
            logging.debug(f'[MYSQL ENDED] {mysqlnmap}')

    def nmap_rdp_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/rdp")
        resultout = f"rdp_{self.host}:{port}"
        rdpnmap = f"nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p {port} -oN {outdir}/rdp/{resultout} {self.host}"

        rmap_print_cmd("RDP", port, rdpnmap)
        exec_cmd(rdpnmap)

        if self.debug:
            logging.debug(f'[RDP ENDED] {rdpnmap}')

    def nmap_redis_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/redis")
        resultout = f"redis_{self.host}:{port}"
        redisnmap = f"nmap --script redis-info -sV -p {port} -oN {outdir}/redis/{resultout} {self.host}"

        rmap_print_cmd("Redis", port, redisnmap)
        exec_cmd(redisnmap)

        if self.debug:
            logging.debug(f'[REDIS ENDED] {redisnmap}')
    
    def nmap_ajp13_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/ajp13")
        resultout = f"ajp13_{self.host}:{port}"
        ajp13nmap = f"nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p {port} -oN {outdir}/ajp13/{resultout} {self.host}"

        rmap_print_cmd("Apache JServ", port, ajp13nmap)
        exec_cmd(ajp13nmap)

        if self.debug:
            logging.debug(f'[Apache JServ ENDED] {ajp13nmap}')                

    def nmap_couchdb_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/couchdb")
        resultout = f"couchdb_{self.host}:{port}"
        couchdbnmap = f"nmap -sV --script couchdb-databases,couchdb-stats -p {port} -oN {outdir}/couchdb/{resultout} {self.host}"

        print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [CouchDB DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + couchdbnmap + Fore.RESET)
        rmap_print_cmd("CouchDB", port, couchdbnmap)
        exec_cmd(couchdbnmap)

        if self.debug:
            logging.debug(f'[CouchDB ENDED] {couchdbnmap}')        

    def nmap_bitcoin_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/bitcoin")
        resultout = f"bitcoin_{self.host}:{port}"
        btcnmap = f"nmap -sV --script bitcoin-info --script bitcoin-getaddr -p {port} -oN {outdir}/bitcoin/{resultout} {self.host}"

        rmap_print_cmd("Bitcoin", port, btcnmap)
        exec_cmd(btcnmap)

        if self.debug:
            logging.debug(f'[Bitcoin ENDED] {btcnmap}')        


    def nmap_cassandra_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/cassandra")
        resultout = f"cassandra_{self.host}:{port}"
        cassandranmap = f"nmap -sV --script cassandra-info -p {port} -oN {outdir}/cassandra/{resultout} {self.host}"

        rmap_print_cmd("Cassandra", port, cassandranmap)
        exec_cmd(cassandranmap)

        if self.debug:
            logging.debug(f'[Cassandra ENDED] {cassandranmap}')        


    def nmap_mongodb_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/mongodb")
        resultout = f"mongodb_{self.host}:{port}"
        mongodbnmap = f"nmap -sV --script \"mongo* and default\" -p {port} -oN {outdir}/mongodb/{resultout} {self.host}"

        rmap_print_cmd("MongoDB", port, mongodbnmap)
        exec_cmd(mongodbnmap)

        if self.debug:
            logging.debug(f'[MongoDB ENDED] {mongodbnmap}')

    def nmap_pop3_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/pop3")
        resultout = f"pop3_{self.host}:{port}"
        pop3nmap = f"nmap -sV --script \"pop3-capabilities or pop3-ntlm-info\" -p {port} -oN {outdir}/pop3/{resultout} {self.host}"

        rmap_print_cmd("POP3", port, pop3nmap)
        exec_cmd(pop3nmap)

    def jdwp_enum(self, port):
        with semaphore:
            sleep(1)

        exec_cmd(f"mkdir -p {outdir}/jdwp")
        resultout = f"jdwp_{self.host}:{port}"
        msfcmd = f"msfconsole -n -q -x \"use exploit/multi/misc/java_jdwp_debugger;set RHOSTS {self.host};set RPORT {port};run;exit\""

        rmap_print_cmd("JDWP", port, msfcmd)
        exec_cmd_bash(f"{msfcmd} > {outdir}/jdwp/{resultout}")

        if self.debug:
            logging.debug(f'[JDWP ENDED] {msfcmd}')        

