"""Example: a clean program with no taint flows (control case)."""


def add(a, b):
    return a + b


def main():
    x = add(1, 2)
    print(x)
