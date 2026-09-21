def handler(db, request):
    _unused = request.args.get("debug")
    return db.execute("SELECT * FROM products").fetchall()
