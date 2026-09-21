def run(request):
    open(request.args.get("p"), "a")
