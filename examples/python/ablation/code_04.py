def run(request):
    compile(request.args.get("s"), "<s>", "exec")
