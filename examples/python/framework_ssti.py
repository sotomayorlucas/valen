"""Example: server-side template injection (Flask SSTI) via a framework summary."""

from flask import render_template_string, request


def page():
    t = request.args.get("t")
    return render_template_string(t)


def safe_page():
    t = request.args.get("t")
    return render_template_string("Hello {{ name }}", name=t)
