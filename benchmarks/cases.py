"""Labeled benchmark corpus (toy, illustrative).

Mix of true positives (vulnerable) and true negatives (safe / mitigated). Two
cases are deliberate *limitations* of the current intraprocedural taint pass:
``interproc_sqli`` (taint across a function boundary) and ``reentrancy`` (no
taint sink; only the topological H1 signal reveals the recursion cycle).
"""

from manifold.benchmark import Case

CASES = [
    # ---- true positives -------------------------------------------------
    Case(
        "sqli_concat",
        "def search(db, q):\n"
        "    sql = \"SELECT * FROM u WHERE n = '\" + q + \"'\"\n"
        "    db.execute(sql)\n",
        True,
    ),
    Case(
        "cmd_injection",
        "import subprocess\n"
        "def ping(h):\n"
        "    subprocess.run('ping -c 1 ' + h, shell=True)\n",
        True,
    ),
    Case(
        "eval_injection",
        "def f(expr):\n    return eval(expr)\n",
        True,
    ),
    Case(
        "env_to_system",
        "import os\n"
        "def f():\n"
        "    cmd = os.environ.get('CMD')\n"
        "    os.system(cmd)\n",
        True,
    ),
    Case(
        "pickle_deserialize",
        "import pickle\n"
        "def f(blob):\n    return pickle.loads(blob)\n",
        True,
    ),
    Case(
        "reentrancy",
        "def withdraw(a):\n"
        "    b = read_balance()\n"
        "    if b >= a:\n"
        "        update_balance(b - a)\n"
        "\n"
        "def read_balance():\n"
        "    return update_balance(0)\n"
        "\n"
        "def update_balance(v):\n"
        "    return read_balance()\n",
        True,
    ),
    Case(
        "interproc_sqli",
        "def get_query(p):\n"
        "    return p\n"
        "\n"
        "def search(db, q):\n"
        "    sql = get_query(q)\n"
        "    db.execute(sql)\n",
        True,
    ),
    # ---- true negatives -------------------------------------------------
    Case(
        "safe_arithmetic",
        "def add(a, b):\n    return a + b\n",
        False,
    ),
    Case(
        "parameterized_query",
        "def search(db, q):\n"
        "    db.execute('SELECT * FROM u WHERE n = ?', (q,))\n",
        False,
    ),
    Case(
        "argv_subprocess",
        "import subprocess\n"
        "def ping(h):\n"
        "    subprocess.run(['ping', '-c', '1', h])\n",
        False,
    ),
    Case(
        "shlex_sanitized",
        "import shlex, subprocess\n"
        "def ping(h):\n"
        "    subprocess.run('ping -c 1 ' + shlex.quote(h), shell=True)\n",
        False,
    ),
    Case(
        "numeric_cast",
        "def f(x):\n"
        "    n = int(x)\n"
        "    return n + 1\n",
        False,
    ),
]
