import shlex


def handler(db, request):
    host = request.args.get("host")
    os.system("ping -c1 " + shlex.quote(host))
