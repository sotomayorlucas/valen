"""Missing authorization (CWE-862): a privileged mutation with no gate.

``delete_user`` mutates a resource based on user input but has no authorization
gate, so any caller can delete arbitrary users. Note this is *also* a taint
finding (``uid`` is untainted-cast-free), but the trust/logic signal is the
absent privilege boundary, independent of injection.
"""


def delete_user(db, request):
    uid = request.args.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
