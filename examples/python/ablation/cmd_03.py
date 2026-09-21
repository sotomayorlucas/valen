def run(request):
    import os
    os.popen("cat " + request.form.get("f"))
