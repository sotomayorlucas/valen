def run(request):
    import os
    os.system("ping " + request.args.get("host"))
