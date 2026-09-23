"""Multi-language ingest: every registered C-like adapter detects taint."""

import pytest

from valen.ingest import LANGUAGE_TO_INGEST, analyze, infer_adapter

# (adapter, vulnerable snippet) — each must produce at least one finding.
SAMPLES = [
    ("c", 'void f(){ char *c=getenv("X"); system(c); }'),
    ("c", 'void f(){ char b[8]; gets(b); system(b); }'),
    ("cpp", 'void f(){ char b[8]; fgets(b,8,stdin); system(b); }'),
    ("rust", 'fn main(){ let s = std::env::args().nth(1).unwrap();'
             ' std::process::Command::new(s); }'),
    ("csharp", 'class T { static void Main(string[] args){ Process.Start(args[0]); } }'),
    ("go", 'package main\nimport ("os";"os/exec")\nfunc f(){ exec.Command(os.Args[1]) }'),
    ("php", '<?php $q=$_GET["x"]; system($q); ?>'),
    ("ruby", 'def f\n  system gets\nend'),
    ("javascript", 'const x = process.argv[2]; require("child_process").exec(x);'),
    ("java", 'class T { void f(HttpServletRequest r){'
             ' Runtime.getRuntime().exec(r.getParameter("cmd")); } }'),
]

EXT_SAMPLES = [
    ("t.c", "c"),
    ("t.cpp", "cpp"),
    ("t.rs", "rust"),
    ("t.cs", "csharp"),
    ("t.go", "go"),
    ("t.php", "php"),
    ("t.rb", "ruby"),
    ("t.js", "javascript"),
    ("t.ts", "javascript"),
    ("t.java", "java"),
    ("t.py", "python"),
]


@pytest.mark.parametrize("adapter,code", SAMPLES)
def test_adapter_detects_taint(adapter, code):
    result = analyze(code, path="t", adapter=adapter)
    assert result.findings, f"{adapter} produced no findings"
    assert any(f.sink_name for f in result.findings)


@pytest.mark.parametrize("path,expected", EXT_SAMPLES)
def test_infer_adapter_extensions(path, expected):
    assert infer_adapter("", path) == expected


def test_all_clike_adapters_registered():
    for name in ("c", "cpp", "rust", "csharp", "go", "php", "ruby", "javascript"):
        assert name in LANGUAGE_TO_INGEST


def test_examples_directory_multilang():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "examples"
    for name in ("c/command_injection.c", "cpp/command_injection.cpp",
                 "rust/command_injection.rs", "csharp/command_injection.cs",
                 "go/command_injection.go", "php/command_injection.php",
                 "ruby/command_injection.rb", "javascript/command_injection.js",
                 "java/command_injection.java"):
        p = root / name
        assert p.exists(), f"missing example {name}"
        result = analyze(p.read_text(), path=str(p))
        assert result.findings, f"{name} produced no findings"
