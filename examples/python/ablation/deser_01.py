def run(request):
    import pickle
    pickle.loads(request.data)
