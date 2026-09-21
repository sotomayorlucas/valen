def handler(db, request):
    uid = request.args.get("uid")
    role = request.args.get("role")
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
