def login_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper

@login_required
def run(db, request):
    db.execute("SELECT * FROM t WHERE x='" + request.args.get("x") + "'")
