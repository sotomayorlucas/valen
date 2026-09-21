"""Taint profiles: per-language sources (untrusted input) and sinks (dangerous ops).

A *source* is an operation that introduces untrusted data into the program.
A *sink* is an operation that must never consume untrusted data.

Each sink carries a *category* used to derive a severity and to reason about
the kind of vulnerability (e.g. ``sql`` -> SQL injection, ``command`` -> OS
command injection, ``deserialization`` -> insecure deserialization).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class LanguageProfile:
    name: str
    sources: Dict[str, str]  # dotted call name -> description
    sinks: Dict[str, str]  # dotted call name -> category
    sanitizers: Dict[str, str] = field(default_factory=dict)  # kill taint
    auth_gates: Dict[str, str] = field(default_factory=dict)  # privilege boundaries


# Severity ordering per sink category (used to rank findings).
CATEGORY_SEVERITY: Dict[str, str] = {
    "command_execution": "critical",
    "code_execution": "critical",
    "deserialization": "critical",
    "sql": "high",
    "path_traversal": "high",
    "file_write": "medium",
    "logging": "medium",
    "network": "medium",
}

PYTHON = LanguageProfile(
    name="python",
    sources={
        # builtins / stdlib
        "input": "interactive standard input",
        "raw_input": "interactive standard input (py2)",
        "sys.stdin.read": "standard input stream",
        "sys.stdin.readline": "standard input stream",
        "sys.argv": "command-line arguments",
        "os.environ.get": "environment variable",
        "os.environ.getenv": "environment variable",
        "socket.recv": "network socket data",
        "socket.recvfrom": "network socket data",
        "urllib.request.urlopen": "remote HTTP response",
        "urllib.request.urlopen.read": "remote HTTP response body",
        "requests.get": "remote HTTP response",
        "requests.post": "remote HTTP response",
        # web frameworks
        "request.args.get": "HTTP query parameter",
        "request.form.get": "HTTP form field",
        "request.json.get": "HTTP JSON body",
        "request.files.get": "HTTP uploaded file",
        "flask.request.args.get": "HTTP query parameter",
        "django.http.HttpRequest.GET.get": "HTTP query parameter",
        # web frameworks -- attribute-style sources (framework summaries)
        "request.args": "Flask query parameters (attribute source)",
        "request.form": "Flask form fields (attribute source)",
        "request.values": "Flask combined parameters (attribute source)",
        "request.json": "Flask JSON body (attribute source)",
        "request.data": "Flask raw body (attribute source)",
        "request.GET": "Django query parameters (attribute source)",
        "request.POST": "Django POST data (attribute source)",
        "request.FILES": "Django uploaded files (attribute source)",
        "request.COOKIES": "Django cookies (attribute source)",
        "request.body": "Django raw body (attribute source)",
        "request.META": "Django request metadata (attribute source)",
        "self.request.GET": "Django query parameters (attribute source)",
        "self.request.POST": "Django POST data (attribute source)",
        # web frameworks -- .get()/method-style accessor variants
        "request.GET.get": "HTTP query parameter",
        "request.POST.get": "HTTP form field",
        "request.COOKIES.get": "HTTP cookie",
        "request.FILES.get": "HTTP uploaded file",
        "request.values.get": "HTTP combined parameter",
        "request.META.get": "HTTP request metadata",
        "self.request.GET.get": "HTTP query parameter",
        "self.request.POST.get": "HTTP form field",
        # filesystem
        "open": "file contents (untrusted path)",
        "pathlib.Path.read_text": "file contents",
        "pathlib.Path.read_bytes": "file contents",
        "file.read": "file contents",
        "pickle.load": "serialized object",
        "pickle.loads": "serialized object",
        "yaml.load": "YAML document",
        "json.load": "JSON document",
        "json.loads": "JSON document",
    },
    sinks={
        "eval": "code_execution",
        "exec": "code_execution",
        "compile": "code_execution",
        "__import__": "code_execution",
        "importlib.import_module": "code_execution",
        "os.system": "command_execution",
        "os.popen": "command_execution",
        "subprocess.call": "command_execution",
        "subprocess.run": "command_execution",
        "subprocess.Popen": "command_execution",
        "subprocess.check_call": "command_execution",
        "subprocess.check_output": "command_execution",
        "subprocess.getoutput": "command_execution",
        "commands.getoutput": "command_execution",
        "pickle.load": "deserialization",
        "pickle.loads": "deserialization",
        "yaml.load": "deserialization",
        "yaml.unsafe_load": "deserialization",
        "sqlite3.connect.execute": "sql",
        "sqlite3.Connection.execute": "sql",
        "cursor.execute": "sql",
        "connection.execute": "sql",
        "db.execute": "sql",
        # ORM / raw-SQL framework summaries
        "RawSQL": "sql",
        "raw": "sql",
        "extra": "sql",
        "text": "sql",
        "executescript": "sql",
        "cursor.executemany": "sql",
        # template injection (SSTI) framework summaries
        "render_template_string": "code_execution",
        "from_string": "code_execution",
        "open": "file_write",
        "pathlib.Path.open": "file_write",
        "os.remove": "path_traversal",
        "os.unlink": "path_traversal",
        "os.rmdir": "path_traversal",
        "logging.debug": "logging",
        "logging.info": "logging",
        "logging.warning": "logging",
        "logging.error": "logging",
    },
    sanitizers={
        # Casting / validation
        "int": "numeric cast",
        "float": "numeric cast",
        "str": "string cast",
        "bool": "boolean cast",
        # HTML / markup escaping
        "html.escape": "HTML escaping",
        "markupsafe.escape": "HTML escaping",
        "cgi.escape": "HTML escaping",
        "bleach.clean": "HTML sanitization",
        "django.utils.html.escape": "HTML escaping",
        # SQL / shell / regex escaping
        "re.escape": "regex escaping",
        "shlex.quote": "shell quoting",
        "pymysql.escape_string": "SQL escaping",
        # Cryptographic / validation helpers
        "hmac.compare_digest": "constant-time comparison",
        "uuid.UUID": "UUID validation",
    },
    auth_gates={
        # Decorators / functions that mark a privilege boundary.
        "login_required": "authentication gate",
        "permission_required": "authorization gate",
        "require_auth": "authentication gate",
        "auth_required": "authentication gate",
        "authenticate": "authentication gate",
        "check_auth": "authentication gate",
        "is_authenticated": "authentication check",
        "has_permission": "authorization check",
        "require_user": "authentication gate",
        "require_role": "authorization gate",
        "verify_token": "token verification",
        "token_required": "token gate",
        "admin_required": "authorization gate",
        "staff_member_required": "authorization gate",
    },
)

JAVASCRIPT = LanguageProfile(
    name="javascript",
    sources={
        "process.argv": "command-line arguments",
        "process.env": "environment variables",
        "req.body": "HTTP request body",
        "req.query": "HTTP query string",
        "req.params": "HTTP route parameters",
        "document.location": "browser location",
        "document.getElementById": "DOM element",
        "window.location.hash": "URL fragment",
        "localStorage.getItem": "local storage",
        "readFileSync": "file contents",
        "fs.readFileSync": "file contents",
    },
    sinks={
        "eval": "code_execution",
        "Function": "code_execution",
        "exec": "code_execution",
        "child_process.exec": "command_execution",
        "child_process.execSync": "command_execution",
        "child_process.spawn": "command_execution",
        "child_process.fork": "code_execution",
        "document.write": "code_execution",
        "innerHTML": "code_execution",
        "outerHTML": "code_execution",
        "insertAdjacentHTML": "code_execution",
        "JSON.parse": "deserialization",
        "sqlite3.run": "sql",
        "db.query": "sql",
        "db.execute": "sql",
        "connection.query": "sql",
        "fs.writeFileSync": "file_write",
        "fs.writeFile": "file_write",
        "fs.rmSync": "path_traversal",
    },
    sanitizers={
        "escapeHtml": "HTML escaping",
        "encodeURIComponent": "URI encoding",
        "sanitizeHtml": "HTML sanitization",
        "mongo-sanitize": "NoSQL sanitization",
        "validator.escape": "string escaping",
        "Number": "numeric cast",
        "parseInt": "numeric cast",
    },
)

PROFILES: Dict[str, LanguageProfile] = {
    "python": PYTHON,
    "javascript": JAVASCRIPT,
}
