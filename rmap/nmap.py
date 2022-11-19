from rmap.scan import RMap
from libnmap.parser import NmapParser
import multiprocessing


class NmapHandler(RMap):
    def __init__(self, host, debug, processes_limit, nmap_all_ports, pre_os_check, nmap_arguments, vulnscan, ffuf_wordlist, ffuf_outtype, scan_timeout):
        super().__init__(host, debug, processes_limit, nmap_all_ports, pre_os_check, nmap_arguments, vulnscan, ffuf_wordlist, ffuf_outtype, scan_timeout)
        
    def parse_nmap_file(self, path_xml):
        nmap_report = NmapParser.parse_fromfile(path_xml)
        
        services = []

        for host in nmap_report.hosts:
            for serv in host.services:
                services.append(f"{serv.service}:{serv.port}")
                
        return services

    def analyse_nmap(self, services):
        with multiprocessing.Pool(processes=int(self.processes_limit)) as pool:
            start = time.time()
            while time.time() - start <= self.scan_timeout:
                if not any(pool.is_alive() for pool in procs):
                    # All the processes are done, break now.
                    break
                sleep(.1)

                for service in services:
                    service = service.split(":")
                    ### FTP
                    if service[0] == "ftp":
                        pool.apply_async(self.nmap_ftp_enum, [service[1]])
                    ### TELNET
                    if service[0] == "telnet":
                        pool.apply_async(self.nmap_telnet_enum, [service[1]])
                    ### HTTP
                    if service[0] == "http":
                        pool.apply_async(self.ffuf_dir_enum, [service[1]])
                    ### SMTP
                    if service[0] == "smtp":
                        pool.apply_async(self.nmap_smtp_enum, [service[1]])
                    ### RDP
                    if service[0] == "ms-wbt-server":
                        pool.apply_async(self.nmap_rdp_enum, [service[1]])
                    ### IRC
                    if service[0] == "irc":
                        pool.apply_async(self.nmap_irc_enum, [service[1]])
                    ### Redis
                    if service[0] == "redis":
                        pool.apply_async(self.nmap_redis_enum, [service[1]])
                    ### LDAP
                    if service[0] == "ldap":
                        pool.apply_async(self.nmap_ldap_enum, [service[1]])
                    ### MYSQL
                    if service[0] == "mysql":
                        pool.apply_async(self.nmap_mysql_enum, [service[1]])
                    ### Apache JServ
                    if service[0] == "ajp13":
                        pool.apply_async(self.nmap_ajp13_enum, [service[1]])
                    ### Java RMI
                    if service[0] == "java-rmi":
                        pool.apply_async(self.nmap_javarmi_enum, [service[1]])
                    ### MongoDB
                    if service[0] == "mongodb":
                        pool.apply_async(self.nmap_mongodb_enum, [service[1]])
                    ### POP3
                    if service[0] == "pop3":
                        pool.apply_async(self.nmap_pop3_enum, [service[1]])
                    ### SMB
                    if int(service[1]) == 445:
                        pool.apply_async(self.nmap_smb_enum, [service[1]])
                    ### CouchDB
                    if int(service[1]) == 5984 or int(service[1]) == 6984:
                        pool.apply_async(self.nmap_couchdb_enum, [service[1]])
            
            else:
                rmap_print_msg("TIMEOUT", "ABORT", f"Aborting due to timeout")
                for p in procs:
                    p.terminate()
                    p.join()
                


            pool.close()
            pool.join()
