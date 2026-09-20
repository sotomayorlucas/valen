"""Example: a sanitizer (shlex.quote) neutralizes shell injection."""

import shlex
import subprocess


def vulnerable_ping(host):
    cmd = "ping -c 1 " + host
    subprocess.run(cmd, shell=True)


def safe_ping_quoted(host):
    cmd = "ping -c 1 " + shlex.quote(host)
    subprocess.run(cmd, shell=True)
