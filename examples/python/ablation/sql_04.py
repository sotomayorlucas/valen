def run(db, request):
    db.execute("SELECT * FROM t WHERE a='" + request.COOKIES.get("c") + "'")
