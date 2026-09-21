def handler(db, request):
    doc = int(request.args.get("doc"))
    return db.execute("SELECT * FROM documents WHERE id = ?", (doc,)).fetchall()
