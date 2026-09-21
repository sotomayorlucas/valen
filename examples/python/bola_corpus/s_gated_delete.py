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

@admin_required
def handler(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
