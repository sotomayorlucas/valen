def run(request):
    import pickle
    pickle.load(request.files.get("f"))
