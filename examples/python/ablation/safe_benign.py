def run(request):
    return {"q": request.args.get("q")}
