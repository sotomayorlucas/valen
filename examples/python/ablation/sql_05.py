def run(db, request):
    db.execute("DELETE FROM t WHERE id=" + request.args.get("id"))
