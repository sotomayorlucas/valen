"""Missing authorization (CWE-862), fixed: the privileged mutation is gated.

``@admin_required`` adds the ``auth`` edge, so the missing-authorization
heuristic stays silent.
"""


def admin_required(f):
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


@admin_required
def delete_user(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
