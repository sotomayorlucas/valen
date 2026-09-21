def helper(request):
    return request.args.get("id")


def handler(db):
    return db.execute("SELECT * FROM orders").fetchall()
