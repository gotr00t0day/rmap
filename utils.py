import pexpect

exec_timeout = 86400 # 24 hours


def exec_cmd(cmd_str):
    return pexpect.run(cmd_str, encoding='utf-8', timeout=exec_timeout)


def exec_cmd_bash(cmd_str):
    p = pexpect.spawn('/bin/bash', ['-c', cmd_str], encoding='utf-8')
    p.expect(pexpect.EOF, exec_timeout)

    p.close()
    return p.before, p.exitstatus