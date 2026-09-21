def handler(db, request):
    path = request.args.get("p")
    open("/var/data/" + path, "w").write(request.data)
