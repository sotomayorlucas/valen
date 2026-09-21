"""BOLA / IDOR (CWE-639), fixed variant A: behind an authentication gate.

Same lookup, but ``@login_required`` introduces an ``auth`` edge, so the
missing-authorization heuristic stays silent. (Crossing is an H4 concern.)
"""


def login_required(f):
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


@login_required
def get_order(db, request):
    order_id = int(request.args.get("id"))
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return row
