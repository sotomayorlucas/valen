def handler(db):
    return db.execute("SELECT * FROM config WHERE key = ?", ("timeout",)).fetchall()
