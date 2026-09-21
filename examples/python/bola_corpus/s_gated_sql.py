def login_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper


def admin_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper


def permission_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper

@login_required
def handler(db, request):
    oid = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
