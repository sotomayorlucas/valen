"""Tests for the dynamic-analysis layer (sandboxed execution + triangulation)."""

from pathlib import Path

from valen.dynamic import run_module, triangulate
from valen.ingest.python import PythonIngest

SQLI = '''import sys, sqlite3


def search(name):
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    cursor.execute(sql)
    return cursor.fetchall()


if __name__ == "__main__":
    search(sys.argv[1])
'''


def _write(tmp_path: Path, code: str) -> str:
    p = tmp_path / "target.py"
    p.write_text(code)
    return str(p)


def _sink_lines(report):
    return {a["line"] for a in report["agreement"] if a["sink_name"]}


def test_run_module_captures_sql_sink(tmp_path):
    target = _write(tmp_path, SQLI)
    dyn = run_module(target, argv=["O'Reilly"])
    assert dyn.exit_code == 1  # sqlite rejects the malformed-but-reached query
    sinks = [s for s in dyn.sinks if s["category"] == "sql"]
    assert sinks
    # the trace captures the concrete argument value that reached the sink
    assert 'Reilly' in str(sinks[0]["args"])


def test_triangulate_confirms_sql(tmp_path):
    target = _write(tmp_path, SQLI)
    result = PythonIngest().analyze(Path(target).read_text(), path=target)
    dyn = run_module(target, argv=["O'Reilly"])
    report = triangulate(result, dyn)
    # the executed sink is confirmed with a concrete value
    assert any(a["dynamic"] == "confirmed" and a["matched_value"]
               for a in report["agreement"])


def test_triangulate_unexecuted_sink(tmp_path):
    code = SQLI + '''\ndef also_unsafe(name):
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM t WHERE x = '" + name + "'")
'''
    target = _write(tmp_path, code)
    result = PythonIngest().analyze(Path(target).read_text(), path=target)
    dyn = run_module(target, argv=["x"])
    report = triangulate(result, dyn)
    # the sink inside also_unsafe is never executed
    assert any(a["dynamic"] == "unexecuted" for a in report["agreement"])


def test_sandbox_isolation_runs_in_clean_cwd(tmp_path):
    target = _write(tmp_path, 'import os\nprint(os.getcwd())\n')
    dyn = run_module(target)
    assert dyn.exit_code == 0
    assert "valen-dyn-" in dyn.stdout


def test_timeout_is_soft(tmp_path):
    target = _write(tmp_path, 'import time\nwhile True: time.sleep(0.1)\n')
    dyn = run_module(target, timeout=2.0)
    assert dyn.timed_out
    assert dyn.exit_code == -9


def test_reproducible_evidence_hash(tmp_path):
    target = _write(tmp_path, SQLI)
    d1 = run_module(target, argv=["x"])
    d2 = run_module(target, argv=["x"])
    assert d1.evidence["sha256_target"] == d2.evidence["sha256_target"]
    assert d1.coverage == d2.coverage
