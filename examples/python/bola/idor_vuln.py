"""BOLA / IDOR (CWE-639): a clean object selector reaches a resource sink, ungated.

The selector is cast to ``int`` so *taint analysis is blind* (the data is clean),
yet user A can read user B's row because the function performs a user-controlled
resource lookup with NO authorization gate. VALEN's structural signal is the
ungated source -> resource-sink pattern, not a taint flow.
"""


def get_order(db, request):
    order_id = int(request.args.get("id"))  # clean (cast) object selector
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return row
