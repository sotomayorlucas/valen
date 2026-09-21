from jinja2 import Template

def run(request):
    return Template(request.args.get("t")).render()
