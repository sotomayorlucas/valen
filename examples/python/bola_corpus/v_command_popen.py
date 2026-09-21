def handler(db, request):
    q = request.POST.get("q")
    os.popen("grep " + q + " /var/log/app.log").read()
