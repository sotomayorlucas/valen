def handler(db, request):
    uid = request.GET.get("uid")
    return db.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
