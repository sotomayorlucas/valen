def search(db, q):
    sql = "SELECT * FROM users WHERE name = '" + q + "'"
    db.execute(sql)
