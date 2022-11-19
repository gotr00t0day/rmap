from rmap.utils import exec_cmd, exec_cmd_bash, rmap_print_cmd
from time import sleep
import logging
from base64 import b64encode

outdir = "rmap-report"

def get_ping_ttl(host):

    p = subprocess.Popen(["ping", "-c 1", host], stdout=subprocess.PIPE)
    res = p.communicate()[0]
    if p.returncode > 0:
        return None
    else:
        pattern = re.compile(r'[t,T][t,T][l,L]=\d*')
        ttl_group = pattern.search(str(res)).group()
        result_ttl = re.findall(r'\d+', ttl_group)

        return int(result_ttl[0])

def jdwp_enum(port=8888):

    hostadd = "127.0.0.1"

    exec_cmd(f"mkdir -p {outdir}/jdwp")

    awkcmd = ''' awk '{for (I=1;I<NF;I++) if ($I == "OS:") printf $(I+1) " " $(I+2)}' '''
    nmapcmd = f'nmap --top-ports 20 -O -oG - {hostadd} | {awkcmd}'
    osresult = exec_cmd_bash(nmapcmd)

    return osresult[0]

  
#print(get_ping_ttl("127.0.0.1"))
jdwp_enum()