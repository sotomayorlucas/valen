def run(db, request):
    db.execute("UPDATE t SET v='" + request.form.get("v") + "'")
