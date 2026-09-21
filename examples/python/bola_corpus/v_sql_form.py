def handler(db, request):
    name = request.form.get("name")
    return db.execute("SELECT * FROM items WHERE name = '" + name + "'").fetchall()
