def run(db, request):
    db.execute("SELECT * FROM t WHERE z='" + request.values.get("z") + "'")
