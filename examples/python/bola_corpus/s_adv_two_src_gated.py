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
    a = request.args.get("a")
    b = request.form.get("b")
    return db.execute("SELECT * FROM t WHERE a=? AND b=?", (a, b)).fetchall()
