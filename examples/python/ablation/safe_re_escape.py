def run(request):
    import re
    return re.escape(request.args.get("p"))
