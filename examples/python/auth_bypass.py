"""Example: a taint flow that crosses an auth boundary (L4 naturality violation).

Both functions have the same SQL-injection flaw, but `admin_delete` sits behind
an `@login_required` gate. The naturality check (L4) tags the first as crossing a
privilege boundary — untrusted data reaches a protected region.
"""

import sqlite3


def login_required(f):
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


@login_required
def admin_delete(query_param):
    query = "DELETE FROM users WHERE " + query_param
    db = sqlite3.connect("app.db")
    db.execute(query)


def public_search(query_param):
    query = "SELECT * FROM users WHERE " + query_param
    db = sqlite3.connect("app.db")
    db.execute(query)
