class View:
    def handler(self, db):
        oid = int(self.request.GET.get("id"))
        return db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchall()
