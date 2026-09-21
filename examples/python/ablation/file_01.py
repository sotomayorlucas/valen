def run(request):
    open("/out/" + request.args.get("p"), "w")
