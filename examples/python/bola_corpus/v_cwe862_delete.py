def handler(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
