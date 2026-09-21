def handler(db, request):
    order_id = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchall()
