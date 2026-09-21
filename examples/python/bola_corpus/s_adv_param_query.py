def handler(db, request):
    uid = request.args.get("uid")
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
