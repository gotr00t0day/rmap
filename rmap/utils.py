import pexpect
import uuid
import os

exec_timeout = 600 # 24 hours

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