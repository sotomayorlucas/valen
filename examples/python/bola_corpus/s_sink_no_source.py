def handler(db):
    return db.execute("SELECT * FROM products").fetchall()
