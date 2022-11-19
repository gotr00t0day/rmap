from rmap.scan import RMap
from libnmap.parser import NmapParser
import multiprocessing


class NmapHandler(RMap):
    def __init__(self, host, debug, processes_limit, nmap_all_ports, pre_os_check, nmap_arguments, nmap_vulnscan, ffuf_wordlist, ffuf_outtype):
        super().__init__(host, debug, processes_limit, nmap_all_ports, pre_os_check, nmap_arguments, nmap_vulnscan, ffuf_wordlist, ffuf_outtype)
        
    def parse_nmap_file(self, path_xml):
        nmap_report = NmapParser.parse_fromfile(path_xml)
        
        services = []

        for host in nmap_report.hosts:
            for serv in host.services:
                services.append(f"{serv.service}:{serv.port}")
                
        return services

    def analyse_nmap(self, services):
        with multiprocessing.Pool(processes=int(self.processes_limit)) as pool:
            for service in services:
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
                if service[0] == "mongodb":
                    pool.apply_async(self.nmap_mongodb_enum, [service[1]])
                if service[0] == "pop3":
                    pool.apply_async(self.nmap_pop3_enum, [service[1]])
                if int(service[1]) == 445:
                    pool.apply_async(self.nmap_smb_enum, [service[1]])
                if int(service[1]) == 5984 or int(service[1]) == 6984:
                    pool.apply_async(self.nmap_couchdb_enum, [service[1]])

            pool.close()
            pool.join()
