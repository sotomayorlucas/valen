"""Example: a reentrancy-like cycle (mutually recursive calls).

This is a *topological* signal: the call graph contains a 1-dimensional hole
(cycle), which the TDA layer (F3) will surface even before any taint is
involved.
"""


def withdraw(amount):
    balance = read_balance()
    if balance >= amount:
        send_funds(amount)
        update_balance(balance - amount)


def read_balance():
    return update_balance(0)


def update_balance(value):
    return read_balance()
