"""Generate a larger, varied Python corpus for the LLM ablation.

The small ablation (9 hand-picked examples) confirmed the arbitration boundary:
the LLM adds interpretability, not detection. This generator emits ~40 files
spanning the sink categories (command / code-exec / deserialization /
path-traversal / file-write / logging) plus safe and gated variants, so the
larger ablation can measure *detection/ranking invariance* (LLM-independent) and
*interpretation/reporting delta* (CWE/title) at scale.

Writes examples/python/ablation/*.py.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples" / "python" / "ablation"

GATE = '''def login_required(f):
    def wrapper(*a, **k):
        return f(*a, **k)
    return wrapper
'''

# (name, code) -- each must contain a *confirmed* taint finding (a real sink),
# except the safe/gated variants which carry a sink but are guarded or sanitized.
CASES = {
    # command execution
    "cmd_01": 'def run(request):\n    import os\n    os.system("ping " + request.args.get("host"))\n',
    "cmd_02": 'def run(request):\n    import subprocess\n    subprocess.call(request.args.get("c"), shell=True)\n',
    "cmd_03": 'def run(request):\n    import os\n    os.popen("cat " + request.form.get("f"))\n',
    # code execution
    "code_01": 'def run(request):\n    eval(request.args.get("e"))\n',
    "code_02": 'def run(request):\n    exec(request.POST.get("c"))\n',
    "code_03": 'def run(request):\n    __import__(request.args.get("m"))\n',
    # SQL injection
    "sql_01": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE x=\'" + request.args.get("x") + "\'")\n',
    "sql_02": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE y=" + request.GET.get("y"))\n',
    "sql_03": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE z=\'" + request.values.get("z") + "\'")\n',
    # deserialization
    "deser_01": 'def run(request):\n    import pickle\n    pickle.loads(request.data)\n',
    "deser_02": 'def run(request):\n    import yaml\n    yaml.load(request.body)\n',
    "deser_03": 'def run(request):\n    import pickle\n    pickle.load(request.files.get("f"))\n',
    # path traversal
    "path_01": 'def run(request):\n    import os\n    os.remove("/srv/" + request.args.get("f"))\n',
    "path_02": 'def run(request):\n    import os\n    os.rmdir("/srv/" + request.args.get("d"))\n',
    "path_03": 'def run(request):\n    import os\n    os.unlink("/srv/" + request.args.get("u"))\n',
    # file write
    "file_01": 'def run(request):\n    open("/out/" + request.args.get("p"), "w")\n',
    "file_02": 'def run(request):\n    open(request.args.get("p"), "a")\n',
    # logging (lower severity)
    "log_01": 'def run(request):\n    import logging\n    logging.error("bad " + request.args.get("msg"))\n',
    "log_02": 'def run(request):\n    import logging\n    logging.warning(request.GET.get("w"))\n',
    # SSTI
    "ssti_01": 'from flask import render_template_string\n\ndef run(request):\n    return render_template_string(request.args.get("t"))\n',
    "ssti_02": 'from jinja2 import Template\n\ndef run(request):\n    return Template(request.args.get("t")).render()\n',
    # more SQL
    "sql_04": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE a=\'" + request.COOKIES.get("c") + "\'")\n',
    "sql_05": 'def run(db, request):\n    db.execute("DELETE FROM t WHERE id=" + request.args.get("id"))\n',
    "sql_06": 'def run(db, request):\n    db.execute("UPDATE t SET v=\'" + request.form.get("v") + "\'")\n',
    # command
    "cmd_04": 'def run(request):\n    import os\n    os.system(request.args.get("c"))\n',
    "cmd_05": 'def run(request):\n    import subprocess\n    subprocess.run(request.args.get("c"), shell=True)\n',
    # code exec
    "code_04": 'def run(request):\n    compile(request.args.get("s"), "<s>", "exec")\n',
    # ---- safe / gated / sanitized variants (no confirmed taint finding) ----
    "safe_param_sql": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE x = ?", (request.args.get("x"),))\n',
    "safe_cast_sql": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE id = " + str(int(request.args.get("id"))))\n',
    "safe_shell_quote": 'import shlex\n\ndef run(request):\n    import os\n    os.system("ping " + shlex.quote(request.args.get("host")))\n',
    "gated_sql": GATE + '\n@login_required\ndef run(db, request):\n    db.execute("SELECT * FROM t WHERE x=\'" + request.args.get("x") + "\'")\n',
    "gated_cmd": GATE + '\n@login_required\ndef run(request):\n    import os\n    os.system(request.args.get("c"))\n',
    "gated_code": GATE + '\n@login_required\ndef run(request):\n    eval(request.args.get("e"))\n',
    "safe_escape": 'def run(request):\n    import markupsafe\n    return markupsafe.escape(request.args.get("h"))\n',
    "safe_re_escape": 'def run(request):\n    import re\n    return re.escape(request.args.get("p"))\n',
    "safe_int_param": 'def run(db, request):\n    db.execute("SELECT * FROM t WHERE id = ?", (int(request.args.get("id")),))\n',
    "safe_benign": 'def run(request):\n    return {"q": request.args.get("q")}\n',
    "reentrancy_a": 'def read_balance(a):\n    return update_balance(a)\n\ndef update_balance(a):\n    return read_balance(a)\n',
}


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    for name, code in CASES.items():
        (OUT / f"{name}.py").write_text(code)
    print(f"wrote {len(CASES)} ablation cases to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
