import io, os, re, sqlite3, tempfile, unittest
from openpyxl import Workbook, load_workbook
from servicepro import importer
from servicepro.web import create_app


def xlsx(rows):
    wb = Workbook(); ws = wb.active
    for r in rows:
        ws.append(r)
    b = io.BytesIO(); wb.save(b)
    return b.getvalue()


class ClassifyTests(unittest.TestCase):
    def test_duplicates_in_file_and_db_and_invalid(self):
        rows = [(2, ["A", "98765 43210"]), (3, ["B", "+91-9876543210"]), (4, ["C", "9123456780"]),
                (5, ["D", "12"]), (6, ["", ""]), (7, ["E", "9988776655"])]
        res, blank = importer.classify(rows, {"business_name": 0, "phone": 1}, {"+919123456780": "Existing Co"})
        self.assertEqual([r["kind"] for r in res], ["new", "duplicate_file", "duplicate_db", "invalid", "new"])
        self.assertEqual(blank, 1)
        self.assertIn("row 2", res[1]["reason"])

    def test_mapping_guess_and_dates(self):
        m = importer.guess_mapping(["Shop Name", "Mobile No.", "Contact Name", "Trial Expiry"])
        self.assertEqual((m["phone"], m["customer_name"], m["trial_end_date"]), (1, 2, 3))
        self.assertEqual(importer.parse_date("05/03/2026"), ("2026-03-05", True))
        self.assertEqual(importer.parse_date("garbage"), (None, False))


class AppImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({"DATABASE": os.path.join(self.tmp, "t.db"), "TESTING": True,
                               "ADMIN_EMAIL": "a@x.com", "ADMIN_PASSWORD": "correct-horse-1"})
        self.c = self.app.test_client()
        r = self.c.get("/login")
        self.post("/login", {"email": "a@x.com", "password": "correct-horse-1"})

    def token(self):
        with self.c.session_transaction() as s:
            s.setdefault("csrf", "tok")
            return s["csrf"]

    def post(self, url, data=None, **kw):
        return self.c.post(url, data={**(data or {}), "csrf_token": self.token()}, **kw)

    def db(self):
        return sqlite3.connect(self.app.config["DATABASE"])

    def upload(self, name, data):
        r = self.post("/import", {"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302, r.data)
        pid = int(r.location.rstrip("/").split("/")[-1])
        m = {"map_phone": "1", "map_business_name": "0", "map_customer_name": "2"}
        self.assertEqual(self.post(f"/import/{pid}", m).status_code, 200)
        r = self.post(f"/import/{pid}/confirm", m)
        self.assertEqual(r.status_code, 302)
        return int(r.location.rstrip("/").split("/")[-1])

    def test_requires_login(self):
        self.assertEqual(create_app({"DATABASE": os.path.join(self.tmp, "x.db")}).test_client().get("/customers").status_code, 302)

    def test_pages_render(self):
        self.upload("a.csv", b"Business,Phone,Name\nAlpha,9876543210,Ravi\n")
        for u in ["/", "/customers", "/customers?q=987&status=Not+Contacted&due=overdue&page=1", "/customers?page=abc",
                  "/import", "/report", "/users", "/export?format=csv", "/export?format=xlsx"]:
            self.assertEqual(self.c.get(u).status_code, 200, u)

    def test_csrf_enforced(self):
        self.assertEqual(self.c.post("/logout").status_code, 400)

    def test_import_skips_duplicates_and_never_overwrites(self):
        h = ["Business", "Phone", "Name"]
        i1 = self.upload("a.xlsx", xlsx([h, ["Alpha", 9876543210, "Ravi"], ["Alpha dup", "+91 98765-43210", "Other"],
                                         ["Bad", "123", "X"], ["Beta", "9123456780", "Sita"]]))
        con = self.db()
        self.assertEqual(con.execute("SELECT total,added,duplicates,invalid FROM imports WHERE id=?", (i1,)).fetchone(), (4, 2, 1, 1))
        con.execute("UPDATE customers SET notes='mine', status='Contacted' WHERE phone='+919876543210'"); con.commit()
        i2 = self.upload("b.csv", b"Business,Phone,Name\nOverwrite?,098765 43210,Zed\nGamma,9000000001,Ann\n")
        self.assertEqual(con.execute("SELECT added,duplicates FROM imports WHERE id=?", (i2,)).fetchone(), (1, 1))
        self.assertEqual(con.execute("SELECT business_name,customer_name,notes,status FROM customers WHERE phone='+919876543210'").fetchone(),
                         ("Alpha", "Ravi", "mine", "Contacted"))
        self.assertEqual(con.execute("SELECT COUNT(*) FROM customers").fetchone()[0], 3)
        r = self.c.get(f"/imports/{i1}/skipped?format=xlsx")
        ws = load_workbook(io.BytesIO(r.data)).active
        self.assertEqual(ws.max_row, 3)  # header + duplicate + invalid, nothing silently dropped
        self.assertEqual(self.c.get(f"/imports/{i1}/skipped?format=csv").status_code, 200)

    def test_database_enforces_unique_phone(self):
        con = self.db()
        con.execute("INSERT INTO customers (phone) VALUES ('+919876543210')")
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO customers (phone) VALUES ('+919876543210')")

    def test_followup_and_manual_duplicate(self):
        self.post("/customers/new", {"phone": "9876543210", "business_name": "Z", "status": "Not Contacted"})
        cid = self.db().execute("SELECT id FROM customers").fetchone()[0]
        r = self.post("/customers/new", {"phone": "+91 98765 43210", "status": "Not Contacted"})
        self.assertIn(f"/customers/{cid}", r.location)
        self.post(f"/customers/{cid}/followup", {"contact_date": "2026-10-01", "method": "Call", "issue_type": "Problem",
                                                  "issue": "Invoice print", "next_followup_date": "2026-10-05", "status": "Not Contacted"})
        row = self.db().execute("SELECT status,last_contact_date,next_followup_date FROM customers WHERE id=?", (cid,)).fetchone()
        self.assertEqual(row, ("Contacted", "2026-10-01", "2026-10-05"))
        self.assertIn(b"Invoice print", self.c.get("/report").data)


if __name__ == "__main__":
    unittest.main()
