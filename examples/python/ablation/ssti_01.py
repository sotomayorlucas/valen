from flask import render_template_string

def run(request):
    return render_template_string(request.args.get("t"))
