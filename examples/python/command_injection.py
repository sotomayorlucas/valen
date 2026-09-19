"""Example: OS command injection from a web request."""

import subprocess


def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)


def safe_ping(host):
    subprocess.run(["ping", "-c", "1", host])
