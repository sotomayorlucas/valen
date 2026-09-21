"""Generate a larger, adversarial BOLA/IDOR + missing-authorization corpus.

The small curated corpus (examples/python/bola/, n=6) is a *feasibility* signal.
This generator emits a larger, structurally diverse, *adversarial* corpus
(examples/python/bola_corpus/, n=40) that includes:

* vulnerable cases: ungated user-controlled resource access across several
  sinks (sql / file_write / path_traversal / command_execution) and HTTP sources
  (request.args / GET / POST / form / json / cookies / self.request.*);
* safe cases: gated variants, sink-without-source, source-without-sink,
  source/sink in *different* functions, parameterized queries, and *adversarial*
  cases the structural heuristic should get WRONG (sanitized / parameterized /
  unused source) --- these are what make the measured precision honest.

Labels are assigned by construction (vulnerable = an HTTP source and a resource
sink in the SAME function with NO auth gate). The detector is then scored
against them; adversarial safe cases expose its precision limit.

Writes examples/python/bola_corpus/manifest.json: {filename: vulnerable}.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples" / "python" / "bola_corpus"

GATE_DEFS = '''def login_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper


def admin_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper


def permission_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper
'''

# (name, body_without_decorator, vulnerable) -- body is a single function named `handler`
VULN = {
    "sql_cast_int": '''
def handler(db, request):
    order_id = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchall()
''',
    "sql_no_cast_get": '''
def handler(db, request):
    uid = request.GET.get("uid")
    return db.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
''',
    "sql_form": '''
def handler(db, request):
    name = request.form.get("name")
    return db.execute("SELECT * FROM items WHERE name = '" + name + "'").fetchall()
''',
    "sql_json": '''
def handler(db, request):
    oid = request.json.get("order")
    return db.execute("SELECT * FROM orders WHERE id = " + str(oid)).fetchall()
''',
    "sql_cookies": '''
def handler(db, request):
    sid = request.COOKIES.get("sid")
    return db.execute("SELECT * FROM sessions WHERE id = '" + sid + "'").fetchall()
''',
    "sql_self_request": '''
class View:
    def handler(self, db):
        oid = int(self.request.GET.get("id"))
        return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
''',
    "path_rm": '''
def handler(db, request):
    fname = request.args.get("f")
    os.remove("/srv/uploads/" + fname)
''',
    "file_write": '''
def handler(db, request):
    path = request.args.get("p")
    open("/var/data/" + path, "w").write(request.data)
''',
    "command": '''
def handler(db, request):
    host = request.args.get("host")
    os.system("ping -c1 " + host)
''',
    "command_popen": '''
def handler(db, request):
    q = request.POST.get("q")
    os.popen("grep " + q + " /var/log/app.log").read()
''',
    "cwe862_delete": '''
def handler(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
''',
    "cwe862_setrole": '''
def handler(db, request):
    uid = request.args.get("uid")
    role = request.args.get("role")
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
''',
    "bfla_export": '''
def handler(db, request):
    fmt = request.args.get("fmt")
    rows = db.execute("SELECT * FROM users").fetchall()
    return str(rows) if fmt else rows
''',
    "deser": '''
def handler(db, request):
    blob = request.data
    return pickle.loads(blob)
''',
    "idor_values": '''
def handler(db, request):
    oid = request.values.get("order")
    return db.execute("SELECT * FROM orders WHERE id = " + oid).fetchall()
''',
    "idor_cast_missing_owner": '''
def handler(db, request):
    doc = int(request.args.get("doc"))
    return db.execute("SELECT * FROM documents WHERE id = ?", (doc,)).fetchall()
''',
    "file_body": '''
def handler(db, request):
    name = request.args.get("n")
    open("/uploads/" + name, "wb").write(request.body)
''',
    "sql_subquery_param": '''
def handler(db, request):
    tid = request.GET.get("team")
    q = "SELECT * FROM projects WHERE team = '" + tid + "'"
    return db.execute(q).fetchall()
''',
}

# (name, code, vulnerable=False)
SAFE = {
    # gated variants of vulnerable patterns
    "gated_sql": GATE_DEFS + '''
@login_required
def handler(db, request):
    oid = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
''',
    "gated_delete": GATE_DEFS + '''
@admin_required
def handler(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
''',
    "gated_perm_export": GATE_DEFS + '''
@permission_required
def handler(db, request):
    rows = db.execute("SELECT * FROM users").fetchall()
    return rows
''',
    "gated_command": GATE_DEFS + '''
@admin_required
def handler(db, request):
    host = request.args.get("host")
    os.system("ping -c1 " + host)
''',
    "gated_path": GATE_DEFS + '''
@login_required
def handler(db, request):
    fname = request.args.get("f")
    os.remove("/srv/uploads/" + fname)
''',
    # sink but NO http source
    "sink_no_source": '''
def handler(db):
    return db.execute("SELECT * FROM products").fetchall()
''',
    # source but NO resource sink
    "source_no_sink": '''
def handler(request):
    q = request.args.get("q")
    return {"echo": q}
''',
    # source in one function, sink in another (no same-function flow)
    "cross_function": '''
def helper(request):
    return request.args.get("id")


def handler(db):
    return db.execute("SELECT * FROM orders").fetchall()
''',
    # fully fixed: gate + ownership
    "fixed_owner": GATE_DEFS + '''
@login_required
def handler(db, request):
    oid = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ? AND owner = ?",
                      (oid, request.user.id)).fetchall()
''',
    # parameterized static query, no gate, no source
    "static_query": '''
def handler(db):
    return db.execute("SELECT * FROM config WHERE key = ?", ("timeout",)).fetchall()
''',
    # ---- adversarial: the structural heuristic SHOULD get these WRONG (FP) ----
    # sanitized command (shlex.quote) + no gate
    "adv_sanitized_cmd": '''
import shlex


def handler(db, request):
    host = request.args.get("host")
    os.system("ping -c1 " + shlex.quote(host))
''',
    # parameterized query with source (arg 0 is a literal)
    "adv_param_query": '''
def handler(db, request):
    uid = request.args.get("uid")
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
''',
    # unused source near a sink
    "adv_unused_source": '''
def handler(db, request):
    _unused = request.args.get("debug")
    return db.execute("SELECT * FROM products").fetchall()
''',
    # source reaches a NON-resource sink (logging) -> not in resource categories
    "adv_logging": '''
import logging


def handler(db, request):
    logging.info("user %s viewed", request.args.get("id"))
    return db.execute("SELECT * FROM products").fetchall()
''',
    # gated AND parameterized
    "adv_gated_param": GATE_DEFS + '''
@login_required
def handler(db, request):
    uid = request.args.get("uid")
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
''',
    # benign health check
    "benign_health": '''
def handler():
    return {"status": "ok"}
''',
    # function-parameter source (not HTTP) reaching a sink
    "param_not_http": '''
def handler(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = " + str(user_id)).fetchall()
''',
    # int-cast + ownership check (no gate, but owner-scoped): borderline safe
    "adv_owner_no_gate": '''
def handler(db, request):
    oid = int(request.args.get("id"))
    return db.execute("SELECT * FROM orders WHERE id = ? AND owner = ?",
                      (oid, request.user.id)).fetchall()
''',
    # request.json used but only for a safe read with bound param
    "adv_json_param": '''
def handler(db, request):
    oid = request.json.get("id")
    return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
''',
    # two sources, one sink, but gated
    "adv_two_src_gated": GATE_DEFS + '''
@admin_required
def handler(db, request):
    a = request.args.get("a")
    b = request.form.get("b")
    return db.execute("SELECT * FROM t WHERE a=? AND b=?", (a, b)).fetchall()
''',
    # path join with safe constant prefix and bound use (no traversal sink arg)
    "adv_open_literal": '''
def handler(db, request):
    _x = request.args.get("f")
    return open("/etc/hostname").read()
''',
}


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    manifest = {}
    for name, code in VULN.items():
        (OUT / f"v_{name}.py").write_text(code.lstrip("\n"))
        manifest[f"v_{name}.py"] = True
    for name, code in SAFE.items():
        (OUT / f"s_{name}.py").write_text(code.lstrip("\n"))
        manifest[f"s_{name}.py"] = False

    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    nv = sum(1 for v in manifest.values() if v)
    print(f"wrote {len(manifest)} cases to {OUT.relative_to(ROOT)} ({nv} vulnerable, "
          f"{len(manifest)-nv} safe) + manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
