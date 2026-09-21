def run(request):
    import yaml
    yaml.load(request.body)
