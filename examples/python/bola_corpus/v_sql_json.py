def handler(db, request):
    oid = request.json.get("order")
    return db.execute("SELECT * FROM orders WHERE id = " + str(oid)).fetchall()
