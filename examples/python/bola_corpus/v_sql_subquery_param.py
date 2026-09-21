def handler(db, request):
    tid = request.GET.get("team")
    q = "SELECT * FROM projects WHERE team = '" + tid + "'"
    return db.execute(q).fetchall()
