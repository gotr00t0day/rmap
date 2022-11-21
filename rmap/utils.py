import pexpect
import uuid
import os
from colorama import Fore
import subprocess
import re

exec_timeout = 600

def rmap_print_cmd(proto, port, cmd):
    print(Fore.RED + "[*]" + Fore.GREEN + f' [{port}] [{proto} DETECTED]' + Fore.MAGENTA + f' [EXEC] ' + Fore.BLUE + cmd + Fore.RESET)

def rmap_print_msg(label, op, msg):
    print(Fore.RED + "[*]" + Fore.GREEN + f' [{label}]' + Fore.MAGENTA + f' [{op}] ' + Fore.BLUE + msg + Fore.RESET)

def rmap_print_timeout(cmd):
    print(Fore.RED + "[*]" + Fore.RED + f' [TIMEOUT]' + Fore.MAGENTA + f' [EXIT] ' + Fore.RED + cmd + Fore.RESET)


def get_ping_ttl(host):

    p = subprocess.Popen(["ping", "-c 1", host], stdout=subprocess.PIPE)
    res = p.communicate()[0]
    if p.returncode > 0:
        return 0
    else:
        pattern = re.compile(r'[t,T][t,T][l,L]=\d*')
        ttl_group = pattern.search(str(res)).group()
        result_ttl = re.findall(r'\d+', ttl_group)

        return int(result_ttl[0])


def check_ping(ip):
    response = os.system("ping -c 1 " + ip + " > /dev/null")
    # and then check the response...
    if response == 0:
        pingstatus = True
    else:
        pingstatus = False
    
    return pingstatus


def exec_cmd(cmd_str):
    return pexpect.run(cmd_str, encoding='utf-8', timeout=exec_timeout)


def exec_cmd_bash(cmd_str):
    p = pexpect.spawn('/bin/bash', ['-c', cmd_str], encoding='utf-8')
    p.expect(pexpect.EOF, exec_timeout)

    p.close()
    return p.before, p.exitstatus


def hex_uuid():
    return uuid.uuid4().hex