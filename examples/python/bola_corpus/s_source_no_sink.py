def handler(request):
    q = request.args.get("q")
    return {"echo": q}
