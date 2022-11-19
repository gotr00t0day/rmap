from rmap.utils import exec_cmd, exec_cmd_bash, rmap_print_cmd, get_ping_ttl
from time import sleep
import logging
from base64 import b64encode

outdir = "rmap-report"

def jdwp_enum(port=8888):

    hostadd = "127.0.0.1"

    exec_cmd(f"mkdir -p {outdir}/jdwp")

    awkcmd = ''' awk '{for (I=1;I<NF;I++) if ($I == "OS:") printf $(I+1) " " $(I+2)}' '''
    nmapcmd = f'nmap --top-ports 20 -O -oG - {hostadd} |  {awkcmd}'
    print(exec_cmd_bash(nmapcmd))
  
#print(get_ping_ttl("127.0.0.1"))
jdwp_enum()