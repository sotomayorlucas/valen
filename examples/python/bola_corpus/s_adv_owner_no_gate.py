def handler(db, request):
    oid = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ? AND owner = ?",
                      (oid, request.user.id)).fetchall()
