"""Example: framework-mediated SQL injection (Django request attribute source).

The taint source is a *framework attribute* (`request.GET`), reaching a raw SQL
sink; this is what a framework/library summary lets the analyzer see.
"""

from django.db import connection


def search(request):
    q = request.GET.get("q")
    sql = "SELECT * FROM users WHERE name = '" + q + "'"
    cursor = connection.cursor()
    cursor.execute(sql)


def safe_search(request):
    q = request.GET.get("q")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = %s", (q,))
