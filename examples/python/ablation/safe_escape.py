def run(request):
    import markupsafe
    return markupsafe.escape(request.args.get("h"))
