def run(request):
    import os
    os.unlink("/srv/" + request.args.get("u"))
