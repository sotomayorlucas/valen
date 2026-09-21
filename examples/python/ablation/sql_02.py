def run(db, request):
    db.execute("SELECT * FROM t WHERE y=" + request.GET.get("y"))
