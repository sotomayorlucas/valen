import logging


def handler(db, request):
    logging.info("user %s viewed", request.args.get("id"))
    return db.execute("SELECT * FROM products").fetchall()
