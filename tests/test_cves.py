"""Tests for the CVE harness diff parsing / reverse application."""

from benchmarks.run_cves import _parse, _reverse_apply

DIFF = """diff --git a/pkg/x.py b/pkg/x.py
index 111..222 100644
--- a/pkg/x.py
+++ b/pkg/x.py
@@ -1,4 +1,4 @@
 import os
 def f(value):
-    return eval(value)
+    return safe(value)
     # tail
"""


def test_parse_lists_source_file_and_hunks():
    files = _parse(DIFF)
    assert files[0]["path"] == "pkg/x.py"
    assert files[0]["hunks"]


def test_reverse_apply_recovers_before_revision():
    after = "import os\ndef f(value):\n    return safe(value)\n    # tail\n"
    files = _parse(DIFF)
    before = _reverse_apply(after, files[0]["hunks"])
    assert before == "import os\ndef f(value):\n    return eval(value)\n    # tail\n"


def test_reverse_apply_locates_block_when_offset():
    # a leading line shifts the hunk; the block is still located
    after = "# header\nimport os\ndef f(value):\n    return safe(value)\n    # tail\n"
    files = _parse(DIFF)
    before = _reverse_apply(after, files[0]["hunks"])
    assert before is not None and "eval(value)" in before
