def run(request):
    __import__(request.args.get("m"))
