def handler(db, request):
    blob = request.data
    return pickle.loads(blob)
