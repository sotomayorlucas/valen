def run(request):
    import os
    os.remove("/srv/" + request.args.get("f"))
