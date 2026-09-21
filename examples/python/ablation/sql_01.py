def run(db, request):
    db.execute("SELECT * FROM t WHERE x='" + request.args.get("x") + "'")
