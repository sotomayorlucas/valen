"""BOLA / IDOR (CWE-639), fixed variant B: gate + object-level ownership check.

The query is additionally constrained to the *owner*, so even a forged id cannot
reach another user's row. The structural heuristic stays silent (gated).
"""


def login_required(f):
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


@login_required
def get_order(db, request):
    order_id = int(request.args.get("id"))
    row = db.execute(
        "SELECT * FROM orders WHERE id = ? AND owner = ?",
        (order_id, request.user.id),
    )
    return row
