# Makefile — thin wrapper over the justfile (preferred). `make help` lists targets.
# If you only have make (no just), the common commands are reproduced below.

.PHONY: help test analyze serve pentest

help:
	@just --list 2>/dev/null || printf '%s\n' \
	  "make test        -> .venv/bin/python -m pytest -q" \
	  "make analyze F=examples/python/sqli.py" \
	  "make serve PORT=8000" \
	  "make pentest     -> valen pentest --scope http://127.0.0.1:8888 --goal all --authorize"

test:
	.venv/bin/python -m pytest -q

analyze:
	.venv/bin/python -m valen.cli $(F) $(ARGS)

serve:
	.venv/bin/python -m valen.server --port $(PORT)

pentest:
	.venv/bin/python -m valen.cli pentest --scope $(SCOPE) --goal $(GOAL) --authorize
