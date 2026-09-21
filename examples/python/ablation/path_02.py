def run(request):
    import os
    os.rmdir("/srv/" + request.args.get("d"))
