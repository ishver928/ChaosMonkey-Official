import os
import subprocess

BACKUP_CMD = "tar czf /tmp/backup.tgz /srv/data"


def vuln_system(host):
    os.system("ping -c 1 " + host)  # expect: CM-A002


def vuln_system_fstring(host):
    os.system(f"nslookup {host}")  # expect: CM-A002


def vuln_shell_true(path):
    subprocess.run(f"ls -la {path}", shell=True)  # expect: CM-A002


def vuln_popen(cmd):
    return os.popen(cmd).read()  # expect: CM-A002


def safe_list(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def safe_constant_shell():
    # fp-fixed: shell=True with a constant command cannot be injected
    subprocess.run("ls -la /var/log", shell=True)


def safe_constant_system():
    os.system(BACKUP_CMD)
