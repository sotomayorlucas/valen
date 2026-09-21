def handler(db, request):
    fmt = request.args.get("fmt")
    rows = db.execute("SELECT * FROM users").fetchall()
    return str(rows) if fmt else rows
