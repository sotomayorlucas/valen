def run(db, request):
    db.execute("SELECT * FROM t WHERE id = ?", (int(request.args.get("id")),))
