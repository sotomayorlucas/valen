def handler(db, request):
    sid = request.COOKIES.get("sid")
    return db.execute("SELECT * FROM sessions WHERE id = '" + sid + "'").fetchall()
