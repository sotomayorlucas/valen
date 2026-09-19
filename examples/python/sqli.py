"""Example: SQL injection via string concatenation of untrusted input."""

import sqlite3


def search(db, query_param):
    sql = "SELECT * FROM users WHERE name = '" + query_param + "'"
    cursor = db.cursor()
    cursor.execute(sql)
    return cursor.fetchall()


def safe_search(db, query_param):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (query_param,))
    return cursor.fetchall()
