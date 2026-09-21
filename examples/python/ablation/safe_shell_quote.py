import shlex

def run(request):
    import os
    os.system("ping " + shlex.quote(request.args.get("host")))
