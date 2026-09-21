def run(request):
    import logging
    logging.error("bad " + request.args.get("msg"))
