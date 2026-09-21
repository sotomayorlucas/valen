def handler(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = " + str(user_id)).fetchall()
