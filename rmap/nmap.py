from rmap.scan import RMap
from libnmap.parser import NmapParser
import multiprocessing


class NmapHandler(RMap):
    def __init__(self, host, debug, processes_limit, all_ports, arguments, vulnscan, ffuf_wordlist, ffuf_outtype, ffuf_recursion, ffuf_depth, ffuf_arguments):
        super().__init__(host, debug, processes_limit, all_ports, arguments, vulnscan, ffuf_wordlist, ffuf_outtype, ffuf_recursion, ffuf_depth, ffuf_arguments)
        
    def parse_file(self, path_xml):
        report = NmapParser.parse_fromfile(path_xml)
        
        services = []

        for host in report.hosts:
            for serv in host.services:
                services.append(f"{serv.port}:{serv.service}:{serv.banner}")
                
        return services

    def analyse_nmap(self, services):
        with multiprocessing.Pool(processes=int(self.processes_limit)) as pool:
            for service in services:
                service = service.split(":")
                ### FTP
                if service[1] == "ftp":
                    pool.apply_async(self.ftp_enum, [service[0]])
                ### TELNET
                if service[1] == "telnet":
                    pool.apply_async(self.telnet_enum, [service[0]])
                ### HTTP
                if service[1] == "http":
                    pool.apply_async(self.ffuf_dir_enum, [service[0]])
                ### SMTP
                if service[1] == "smtp":
                    pool.apply_async(self.smtp_enum, [service[0]])
                ### RDP
                if service[1] == "ms-wbt-server":
                    pool.apply_async(self.rdp_enum, [service[0]])
                ### IRC
                if service[1] == "irc":
                    pool.apply_async(self.irc_enum, [service[0]])
                ### Redis
                if service[1] == "redis":
                    pool.apply_async(self.redis_enum, [service[0]])
                ### LDAP
                if service[1] == "ldap":
                    pool.apply_async(self.ldap_enum, [service[0]])
                ### MYSQL
                if service[1] == "mysql":
                    pool.apply_async(self.mysql_enum, [service[0]])
                ### Apache JServ
                if service[1] == "ajp13":
                    pool.apply_async(self.ajp13_enum, [service[0]])
                ### Java RMI
                if service[1] == "java-rmi":
                    pool.apply_async(self.javarmi_enum, [service[0]])
                ### MongoDB
                if service[1] == "mongodb":
                    pool.apply_async(self.mongodb_enum, [service[0]])
                ### POP3
                if service[1] == "pop3":
                    pool.apply_async(self.pop3_enum, [service[0]])
                ### NFS
                if service[1] == "nfs":
                    pool.apply_async(self.nfs_enum, [service[0]])
                ### AMQP (advanced message queuing protocol)
                if service[1] == "amqp":
                    pool.apply_async(self.amqp_enum, [service[0]])
                ### SMB
                if int(service[0]) == 445:
                    pool.apply_async(self.smb_enum, [service[0]])
                ### Samba
                if "Samba" in str(service[2]) and str(service[1]) == "netbios-ssn":
                    pool.apply_async(self.samba_enum, [service[0]])
                ### CouchDB
                if int(service[0]) == 5984 or int(service[0]) == 6984:
                    pool.apply_async(self.couchdb_enum, [service[0]])

            pool.close()
            pool.join()
