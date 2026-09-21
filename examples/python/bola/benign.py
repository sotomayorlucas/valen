"""Benign: resource access without a user-controlled selector, and a health check.

``list_products`` runs a resource query but takes no user input, so the
missing-authorization heuristic (which requires an HTTP source) stays silent.
``health`` has neither a source nor a resource sink.
"""


def list_products(db):
    return db.execute("SELECT * FROM products").fetchall()


def health():
    return {"status": "ok"}
