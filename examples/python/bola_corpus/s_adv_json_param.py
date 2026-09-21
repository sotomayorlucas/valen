def handler(db, request):
    oid = request.json.get("id")
    return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
