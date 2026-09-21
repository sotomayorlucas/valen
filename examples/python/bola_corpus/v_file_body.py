def handler(db, request):
    name = request.args.get("n")
    open("/uploads/" + name, "wb").write(request.body)
