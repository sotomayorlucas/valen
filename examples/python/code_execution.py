"""Example: code execution via eval/exec of untrusted input."""

import os


def evaluate(expr):
    return eval(expr)


def run_command_from_env():
    cmd = os.environ.get("CMD")
    os.system(cmd)


def insecure_deserialize(blob):
    import pickle

    return pickle.loads(blob)
