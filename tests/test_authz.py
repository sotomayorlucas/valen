"""Tests for authentication/authorization (users, roles, sessions)."""


import pytest

from valen.authz import Authz, bootstrap_admin, role_can


def test_bootstrap_admin(tmp_path):
    az = Authz(str(tmp_path / "d"))
    assert not az.has_users()
    admin = bootstrap_admin(az, "root")
    assert admin["username"] == "root" and admin["role"] == "admin"
    assert admin["generated_password"]
    # can log in with the generated password
    assert az.authenticate("root", admin["generated_password"])["role"] == "admin"


def test_create_and_authenticate(tmp_path):
    az = Authz(str(tmp_path / "d"))
    az.create_user("alice", "passw0rd123", "operator")
    assert az.authenticate("alice", "passw0rd123")["username"] == "alice"
    assert az.authenticate("alice", "wrong") is None
    assert az.authenticate("bob", "passw0rd123") is None


def test_password_and_role_validation(tmp_path):
    az = Authz(str(tmp_path / "d"))
    with pytest.raises(ValueError):
        az.create_user("a", "short", "operator")
    with pytest.raises(ValueError):
        az.create_user("b", "passw0rd123", "superuser")
    az.create_user("c", "passw0rd123", "operator")
    with pytest.raises(ValueError):
        az.create_user("c", "passw0rd123", "operator")  # duplicate


def test_sessions_resolve_and_expire(tmp_path):
    az = Authz(str(tmp_path / "d"))
    u = az.create_user("alice", "passw0rd123", "viewer")
    token = az.create_session(u["id"], ttl=3600)
    assert az.resolve(token)["username"] == "alice"
    assert az.resolve("garbage") is None
    az.revoke(token)
    assert az.resolve(token) is None
    # expired session
    token2 = az.create_session(u["id"], ttl=-1)
    assert az.resolve(token2) is None


def test_disabled_user_cannot_login_or_resolve(tmp_path):
    az = Authz(str(tmp_path / "d"))
    u = az.create_user("bob", "passw0rd123", "operator")
    token = az.create_session(u["id"])
    az.set_disabled(u["id"], True)
    assert az.authenticate("bob", "passw0rd123") is None
    assert az.resolve(token) is None


def test_role_capabilities():
    assert role_can("viewer", "read")
    assert not role_can("viewer", "execute")
    assert not role_can("viewer", "manage_users")
    assert role_can("operator", "execute")
    assert not role_can("operator", "manage_users")
    assert role_can("admin", "manage_users")


def test_tokens_are_hashed_not_stored_plaintext(tmp_path):
    import sqlite3

    az = Authz(str(tmp_path / "d"))
    u = az.create_user("alice", "passw0rd123", "operator")
    token = az.create_session(u["id"])
    con = sqlite3.connect(az.db)
    rows = con.execute("SELECT token_hash FROM sessions").fetchall()
    con.close()
    assert rows and all(token not in r[0] for r in rows)
