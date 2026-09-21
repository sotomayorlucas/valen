def run(request):
    import logging
    logging.warning(request.GET.get("w"))
