def run(db, request):
    db.execute("SELECT * FROM t WHERE id = " + str(int(request.args.get("id"))))
