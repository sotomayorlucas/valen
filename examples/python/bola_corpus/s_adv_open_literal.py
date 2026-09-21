def handler(db, request):
    _x = request.args.get("f")
    return open("/etc/hostname").read()
