def handler(db, request):
    oid = request.values.get("order")
    return db.execute("SELECT * FROM orders WHERE id = " + oid).fetchall()
