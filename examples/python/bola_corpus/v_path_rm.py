def handler(db, request):
    fname = request.args.get("f")
    os.remove("/srv/uploads/" + fname)
