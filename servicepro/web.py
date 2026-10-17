import csv, io, json, os, re, secrets, sqlite3, time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

import click
from flask import (Flask, Response, abort, current_app, flash, g, redirect, render_template,
                   request, send_file, session, url_for)
from openpyxl import Workbook
from werkzeug.security import check_password_hash, generate_password_hash

from . import importer
from .constants import CLOSED, ISSUE_TYPES, METHODS, OUTCOMES, STATUSES
from .phone import normalize_phone

ROOT = Path(__file__).resolve().parent.parent
FAILS = {}  # (ip, email) -> [timestamps]; in-memory login throttle
DUMMY_HASH = generate_password_hash("not-a-real-password")


def create_app(config=None):
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    env = os.environ.get("APP_ENV", "development")
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", ""), DATABASE=os.environ.get("DATABASE_PATH", str(ROOT / "instance" / "servicepro.db")),
        TIMEZONE=os.environ.get("APP_TIMEZONE", "Asia/Kolkata"), MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=(env == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12), ADMIN_EMAIL=os.environ.get("ADMIN_EMAIL", ""),
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", ""))
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"]:
        if env == "production":
            raise RuntimeError("SECRET_KEY must be set in production")
        app.config["SECRET_KEY"] = "dev-only-insecure-key"
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    # ---------- database ----------
    def connect():
        c = sqlite3.connect(app.config["DATABASE"], timeout=15)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def db():
        if "db" not in g:
            g.db = connect()
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        c = g.pop("db", None)
        if c:
            c.close()

    def migrate():
        c = connect()
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)")
        done = {r[0] for r in c.execute("SELECT name FROM schema_migrations")}
        for f in sorted((ROOT / "migrations").glob("*.sql")):
            if f.name not in done:
                c.executescript(f.read_text())
                c.execute("INSERT INTO schema_migrations VALUES (?)", (f.name,))
                c.commit()
        if app.config["ADMIN_EMAIL"] and app.config["ADMIN_PASSWORD"] and not c.execute("SELECT 1 FROM users").fetchone():
            c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')",
                      ("Admin", app.config["ADMIN_EMAIL"].strip().lower(), generate_password_hash(app.config["ADMIN_PASSWORD"])))
            c.commit()
        c.close()
    migrate()

    def today():
        return datetime.now(ZoneInfo(app.config["TIMEZONE"])).date()

    # ---------- security ----------
    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]
    app.jinja_env.globals.update(csrf_token=csrf, STATUSES=STATUSES, METHODS=METHODS, OUTCOMES=OUTCOMES,
                                 ISSUE_TYPES=ISSUE_TYPES, CLOSED=CLOSED)
    app.jinja_env.filters["dmy"] = lambda s: datetime.strptime(s, "%Y-%m-%d").strftime("%d %b %Y") if s else "—"

    @app.before_request
    def guard():
        g.user = None
        if session.get("uid"):
            u = db().execute("SELECT * FROM users WHERE id=? AND active=1", (session["uid"],)).fetchone()
            if u:
                g.user = u
            else:
                session.clear()
        if request.method == "POST":
            if not secrets.compare_digest(request.form.get("csrf_token", ""), session.get("csrf", "x")):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")

    @app.after_request
    def headers(r):
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["Referrer-Policy"] = "same-origin"
        r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
        r.headers["Cache-Control"] = "no-store"
        return r

    def login_required(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                return redirect(url_for("login", next=request.full_path if request.method == "GET" else None))
            return f(*a, **k)
        return w

    def admin_required(f):
        @wraps(f)
        @login_required
        def w(*a, **k):
            if g.user["role"] != "admin":
                abort(403)
            return f(*a, **k)
        return w

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def err(e):
        msg = "File is too large (limit 5 MB)." if e.code == 413 else (e.description if e.code == 400 else e.name)
        return render_template("error.html", code=e.code, msg=msg), e.code

    @app.route("/healthz")
    def healthz():
        return "ok"

    # ---------- auth ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            key = (request.remote_addr, email)
            now = time.time()
            FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 900]
            if len(FAILS[key]) >= 5:
                flash("Too many failed attempts. Try again in 15 minutes.", "error")
                return render_template("login.html"), 429
            u = db().execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
            ok = check_password_hash(u["password_hash"] if u else DUMMY_HASH, request.form.get("password", ""))
            if u and ok:
                nxt = request.form.get("next", "")
                session.clear()
                session["uid"], session.permanent = u["id"], True
                csrf()
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
            FAILS[key].append(now)
            flash("Incorrect email or password.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------- dashboard ----------
    @app.route("/")
    @login_required
    def dashboard():
        t = today().isoformat()
        week = (today() + timedelta(days=7)).isoformat()
        open_ = "status NOT IN ('Converted to Paid','Not Interested') AND next_followup_date"
        q = lambda sql, *p: db().execute(sql, p).fetchone()[0]
        stats = {
            "total": q("SELECT COUNT(*) FROM customers"),
            "new": q("SELECT COUNT(*) FROM customers WHERE created_at >= datetime('now','-7 days')"),
            "not_contacted": q("SELECT COUNT(*) FROM customers WHERE status='Not Contacted'"),
            "due": q(f"SELECT COUNT(*) FROM customers WHERE {open_}=?", t),
            "overdue": q(f"SELECT COUNT(*) FROM customers WHERE {open_}<?", t),
            "upcoming": q(f"SELECT COUNT(*) FROM customers WHERE {open_}>? AND next_followup_date<=?", t, week),
            "paid": q("SELECT COUNT(*) FROM customers WHERE status='Converted to Paid'")}
        due = db().execute(f"SELECT c.*, u.name AS staff FROM customers c LEFT JOIN users u ON u.id=c.assigned_to "
                           f"WHERE c.{open_}<=? ORDER BY next_followup_date LIMIT 15", (t,)).fetchall()
        return render_template("dashboard.html", s=stats, due=due, today=t)

    # ---------- customers ----------
    def esc(s):
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def filters(args):
        w, p = [], []
        q = args.get("q", "").strip()[:100]
        if q:
            clause, like = "c.business_name LIKE ? ESCAPE '\\' OR c.customer_name LIKE ? ESCAPE '\\'", f"%{esc(q)}%"
            p += [like, like]
            digits = re.sub(r"\D", "", q)
            if len(digits) >= 3:
                clause += " OR c.phone LIKE ?"
                p.append(f"%{digits}%")
            w.append(f"({clause})")
        if args.get("status") in STATUSES:
            w.append("c.status=?"); p.append(args["status"])
        a = args.get("assigned", "")
        if a == "none":
            w.append("c.assigned_to IS NULL")
        elif a.isdigit():
            w.append("c.assigned_to=?"); p.append(int(a))
        t = today().isoformat()
        open_ = "c.status NOT IN ('Converted to Paid','Not Interested') AND c.next_followup_date"
        due = args.get("due", "")
        if due == "today":
            w.append(f"{open_}=?"); p.append(t)
        elif due == "overdue":
            w.append(f"{open_}<?"); p.append(t)
        elif due == "upcoming":
            w.append(f"{open_}>? AND c.next_followup_date<=?"); p += [t, (today() + timedelta(days=7)).isoformat()]
        if args.get("import_id", "").isdigit():
            w.append("c.import_id=?"); p.append(int(args["import_id"]))
        return (" WHERE " + " AND ".join(w)) if w else "", p

    def staff():
        return db().execute("SELECT id, name FROM users WHERE active=1 ORDER BY name").fetchall()

    @app.route("/customers")
    @login_required
    def customers():
        where, p = filters(request.args)
        pg = request.args.get("page", "1")
        page = max(1, int(pg)) if pg.isdigit() else 1
        total = db().execute(f"SELECT COUNT(*) FROM customers c{where}", p).fetchone()[0]
        rows = db().execute(f"SELECT c.*, u.name AS staff FROM customers c LEFT JOIN users u ON u.id=c.assigned_to{where} "
                            f"ORDER BY c.created_at DESC, c.id DESC LIMIT 50 OFFSET ?", p + [(page - 1) * 50]).fetchall()
        qs = {k: v for k, v in request.args.items() if k != "page" and v}
        return render_template("customers.html", rows=rows, total=total, page=page, pages=(total + 49) // 50,
                               staff=staff(), qs=qs, today=today().isoformat())

    def read_customer_form(f):
        e, d = [], {}
        phone, perr = normalize_phone(f.get("phone", ""))
        if perr:
            e.append(f"Phone: {perr}")
        d["phone"] = phone
        d["business_name"], d["customer_name"] = f.get("business_name", "").strip()[:200], f.get("customer_name", "").strip()[:200]
        d["feedback"], d["notes"] = f.get("feedback", "").strip()[:5000], f.get("notes", "").strip()[:5000]
        d["status"] = f.get("status", "Not Contacted")
        if d["status"] not in STATUSES:
            e.append("Invalid status")
        d["contact_method"] = f.get("contact_method", "")
        if d["contact_method"] not in METHODS + [""]:
            e.append("Invalid contact method")
        for k in ("trial_end_date", "next_followup_date", "last_contact_date"):
            v = f.get(k, "").strip() or None
            if v:
                try:
                    datetime.strptime(v, "%Y-%m-%d")
                except ValueError:
                    e.append(f"Invalid date for {k.replace('_', ' ')}")
            d[k] = v
        a = f.get("assigned_to", "")
        d["assigned_to"] = int(a) if a.isdigit() and db().execute("SELECT 1 FROM users WHERE id=?", (int(a),)).fetchone() else None
        d["paid"] = 1 if d["status"] == "Converted to Paid" else 0
        return d, e

    COLS = ["phone", "business_name", "customer_name", "trial_end_date", "status", "feedback", "next_followup_date",
            "notes", "assigned_to", "last_contact_date", "contact_method", "paid"]

    @app.route("/customers/new", methods=["GET", "POST"])
    @login_required
    def customer_new():
        c = request.form.to_dict() if request.method == "POST" else {"status": "Not Contacted"}
        if request.method == "POST":
            d, errs = read_customer_form(request.form)
            if not errs:
                try:
                    cur = db().execute(f"INSERT INTO customers ({','.join(COLS)}) VALUES ({','.join('?' * len(COLS))})",
                                       [d[k] for k in COLS])
                    db().commit()
                    flash("Customer added.", "ok")
                    return redirect(url_for("customer", cid=cur.lastrowid))
                except sqlite3.IntegrityError:
                    ex = db().execute("SELECT id FROM customers WHERE phone=?", (d["phone"],)).fetchone()
                    errs = [f"This phone number already exists. Open the existing customer instead."]
                    if ex:
                        return redirect(url_for("customer", cid=ex["id"]))
            for x in errs:
                flash(x, "error")
        return render_template("customer.html", c=c, new=True, staff=staff(), history=[])

    @app.route("/customers/<int:cid>", methods=["GET", "POST"])
    @login_required
    def customer(cid):
        c = db().execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone() or abort(404)
        if request.method == "POST":
            d, errs = read_customer_form(request.form)
            if not errs:
                try:
                    db().execute(f"UPDATE customers SET {','.join(k + '=?' for k in COLS)}, updated_at=datetime('now') WHERE id=?",
                                 [d[k] for k in COLS] + [cid])
                    db().commit()
                    flash("Saved.", "ok")
                    return redirect(url_for("customer", cid=cid))
                except sqlite3.IntegrityError:
                    errs = ["Another customer already uses that phone number."]
            for x in errs:
                flash(x, "error")
            c = {**dict(c), **request.form.to_dict()}
        hist = db().execute("SELECT f.*, u.name AS staff FROM followups f LEFT JOIN users u ON u.id=f.user_id "
                            "WHERE customer_id=? ORDER BY contact_date DESC, f.id DESC", (cid,)).fetchall()
        return render_template("customer.html", c=c, new=False, staff=staff(), history=hist, today=today().isoformat())

    @app.route("/customers/<int:cid>/followup", methods=["POST"])
    @login_required
    def add_followup(cid):
        c = db().execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone() or abort(404)
        f, errs = request.form, []
        def date_or_none(k, required=False):
            v = f.get(k, "").strip()
            if not v:
                if required:
                    errs.append("Contact date is required")
                return None
            try:
                datetime.strptime(v, "%Y-%m-%d")
                return v
            except ValueError:
                errs.append(f"Invalid {k.replace('_', ' ')}")
        cd, nd = date_or_none("contact_date", True), date_or_none("next_followup_date")
        method, outcome = f.get("method", ""), f.get("outcome", "")
        itype, status = f.get("issue_type", ""), f.get("status", c["status"])
        if method not in METHODS + [""] or itype not in ISSUE_TYPES + [""] or status not in STATUSES:
            errs.append("Invalid selection")
        if errs:
            for x in errs:
                flash(x, "error")
            return redirect(url_for("customer", cid=cid))
        if status == "Not Contacted":
            status = "Contacted"
        db().execute("INSERT INTO followups (customer_id,contact_date,method,outcome,feedback,issue_type,issue,next_action,next_followup_date,user_id)"
                     " VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (cid, cd, method, outcome[:100], f.get("feedback", "").strip()[:5000], itype, f.get("issue", "").strip()[:2000],
                      f.get("next_action", "").strip()[:1000], nd, g.user["id"]))
        last = max(filter(None, [c["last_contact_date"], cd]))
        db().execute("UPDATE customers SET last_contact_date=?, contact_method=?, next_followup_date=?, status=?, paid=?, "
                     "updated_at=datetime('now') WHERE id=?",
                     (last, method or c["contact_method"], nd, status, 1 if status == "Converted to Paid" else 0, cid))
        db().commit()
        flash("Follow-up saved.", "ok")
        return redirect(url_for("customer", cid=cid))

    @app.route("/customers/<int:cid>/delete", methods=["POST"])
    @admin_required
    def customer_delete(cid):
        db().execute("DELETE FROM customers WHERE id=?", (cid,))
        db().commit()
        flash("Customer deleted.", "ok")
        return redirect(url_for("customers"))

    # ---------- export ----------
    def safe(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    def send_table(headers, rows, fmt, name, phone_cols=()):
        rows = [[v if i in phone_cols else safe(v) for i, v in enumerate(r)] for r in rows]
        buf = io.BytesIO()
        if fmt == "csv":
            s = io.StringIO()
            w = csv.writer(s)
            w.writerow(headers); w.writerows(rows)
            buf.write(b"\xef\xbb\xbf" + s.getvalue().encode())
            mime, ext = "text/csv", "csv"
        else:
            wb = Workbook(); ws = wb.active
            ws.append(headers)
            for r in rows:
                ws.append(r)
            wb.save(buf)
            mime, ext = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
        buf.seek(0)
        return send_file(buf, mimetype=mime, as_attachment=True, download_name=f"{name}.{ext}")

    @app.route("/export")
    @login_required
    def export():
        where, p = filters(request.args)
        rs = db().execute(f"SELECT c.*, u.name AS staff FROM customers c LEFT JOIN users u ON u.id=c.assigned_to{where} ORDER BY c.id", p).fetchall()
        h = ["Business name", "Customer name", "Phone", "Trial end date", "Status", "Feedback / problem", "Next follow-up",
             "Notes", "Assigned to", "Last contact", "Contact method", "Paid"]
        data = [[r["business_name"], r["customer_name"], r["phone"], r["trial_end_date"], r["status"], r["feedback"],
                 r["next_followup_date"], r["notes"], r["staff"], r["last_contact_date"], r["contact_method"],
                 "Yes" if r["paid"] else "No"] for r in rs]
        return send_table(h, data, request.args.get("format", "xlsx"), "customers", phone_cols=(2,))

    # ---------- import ----------
    def existing_for(rows, mapping):
        phones, out = list(importer.phones_in(rows, mapping)), {}
        for i in range(0, len(phones), 500):
            ch = phones[i:i + 500]
            for r in db().execute(f"SELECT phone, COALESCE(NULLIF(business_name,''), NULLIF(customer_name,''), 'no name') n "
                                  f"FROM customers WHERE phone IN ({','.join('?' * len(ch))})", ch):
                out[r["phone"]] = r["n"]
        return out

    def pending(pid):
        r = db().execute("SELECT * FROM pending_imports WHERE id=? AND user_id=?", (pid, g.user["id"])).fetchone() or abort(404)
        return r, json.loads(r["headers"]), json.loads(r["rows"])

    def mapping_from(form, headers):
        m = {}
        for f, _ in importer.FIELDS:
            v = form.get(f"map_{f}", "")
            if v.isdigit() and int(v) < len(headers):
                m[f] = int(v)
        return m

    @app.route("/import", methods=["GET", "POST"])
    @login_required
    def import_upload():
        if request.method == "POST":
            f = request.files.get("file")
            if not f or not f.filename:
                flash("Choose a file first.", "error")
            else:
                try:
                    headers, rows = importer.read_upload(f.filename, f.read())
                except importer.ImportFileError as ex:
                    flash(str(ex), "error")
                else:
                    db().execute("DELETE FROM pending_imports WHERE created_at < datetime('now','-1 day')")
                    cur = db().execute("INSERT INTO pending_imports (user_id,filename,headers,rows) VALUES (?,?,?,?)",
                                       (g.user["id"], os.path.basename(f.filename)[:200], json.dumps(headers),
                                        json.dumps([[n, [None if v is None else (v.isoformat() if hasattr(v, "isoformat") else v) for v in vals]] for n, vals in rows])))
                    db().commit()
                    return redirect(url_for("import_map", pid=cur.lastrowid))
        hist = db().execute("SELECT i.*, u.name AS who FROM imports i LEFT JOIN users u ON u.id=i.user_id ORDER BY i.id DESC LIMIT 20").fetchall()
        return render_template("import_upload.html", hist=hist)

    @app.route("/import/<int:pid>", methods=["GET", "POST"])
    @login_required
    def import_map(pid):
        p, headers, rows = pending(pid)
        rows = [(n, v) for n, v in rows]
        preview = None
        mapping = importer.guess_mapping(headers)
        if request.method == "POST":
            mapping = mapping_from(request.form, headers)
            if "phone" not in mapping:
                flash("Choose which column holds the phone number.", "error")
            else:
                res, blank = importer.classify(rows, mapping, existing_for(rows, mapping))
                counts = {k: sum(1 for r in res if r["kind"] == k) for k in ("new", "duplicate_db", "duplicate_file", "invalid")}
                preview = {"res": res[:100], "counts": counts, "total": len(res), "blank": blank, "shown": min(100, len(res))}
        return render_template("import_map.html", p=p, headers=headers, mapping=mapping, preview=preview,
                               fields=importer.FIELDS)

    @app.route("/import/<int:pid>/confirm", methods=["POST"])
    @login_required
    def import_confirm(pid):
        p, headers, rows = pending(pid)
        mapping = mapping_from(request.form, headers)
        if "phone" not in mapping:
            abort(400, "Phone column not mapped.")
        res, blank = importer.classify(rows, mapping, existing_for(rows, mapping))
        c = db()
        cur = c.execute("INSERT INTO imports (filename,user_id,headers,total,added,duplicates,invalid,blank) VALUES (?,?,?,0,0,0,0,?)",
                        (p["filename"], g.user["id"], json.dumps(headers), blank))
        iid, added = cur.lastrowid, 0
        skipped = []
        for r in res:
            kind, reason = r["kind"], r["reason"]
            if kind == "new":
                rec = r["record"]
                try:  # database-level UNIQUE(phone) is the final guard against races
                    c.execute("INSERT INTO customers (phone,business_name,customer_name,trial_end_date,status,feedback,notes,paid,import_id)"
                              " VALUES (?,?,?,?,?,?,?,?,?)",
                              (rec["phone"], rec["business_name"], rec["customer_name"], rec["trial_end_date"], rec["status"],
                               rec["feedback"], rec["notes"], 1 if rec["status"] == "Converted to Paid" else 0, iid))
                    added += 1
                    continue
                except sqlite3.IntegrityError:
                    kind, reason = "duplicate_db", "Already in database (added by someone else during import)"
            skipped.append((iid, r["row_number"], kind, reason, json.dumps(r["values"])))
        c.executemany("INSERT INTO import_skipped (import_id,row_number,category,reason,raw_values) VALUES (?,?,?,?,?)", skipped)
        dup = sum(1 for s in skipped if s[2].startswith("duplicate"))
        c.execute("UPDATE imports SET total=?, added=?, duplicates=?, invalid=? WHERE id=?",
                  (len(res), added, dup, len(skipped) - dup, iid))
        c.execute("DELETE FROM pending_imports WHERE id=?", (pid,))
        c.commit()
        return redirect(url_for("import_result", iid=iid))

    @app.route("/imports/<int:iid>")
    @login_required
    def import_result(iid):
        i = db().execute("SELECT * FROM imports WHERE id=?", (iid,)).fetchone() or abort(404)
        sk = db().execute("SELECT * FROM import_skipped WHERE import_id=? ORDER BY row_number LIMIT 200", (iid,)).fetchall()
        return render_template("import_result.html", i=i, sk=sk)

    @app.route("/imports/<int:iid>/skipped")
    @login_required
    def import_skipped(iid):
        i = db().execute("SELECT * FROM imports WHERE id=?", (iid,)).fetchone() or abort(404)
        sk = db().execute("SELECT * FROM import_skipped WHERE import_id=? ORDER BY row_number", (iid,)).fetchall()
        data = [[s["row_number"], s["category"].replace("_", " "), s["reason"]] + json.loads(s["raw_values"]) for s in sk]
        return send_table(["Row", "Category", "Reason"] + json.loads(i["headers"]), data,
                          request.args.get("format", "xlsx"), f"skipped-rows-import-{iid}")

    # ---------- feedback report ----------
    @app.route("/report")
    @login_required
    def report():
        groups = {}
        for t in ISSUE_TYPES:
            groups[t] = db().execute(
                "SELECT MIN(issue) AS text, COUNT(*) AS n, COUNT(DISTINCT customer_id) AS customers FROM followups "
                "WHERE issue_type=? AND TRIM(issue)<>'' GROUP BY LOWER(TRIM(issue)) ORDER BY n DESC, text LIMIT 25", (t,)).fetchall()
        recent = db().execute("SELECT f.feedback, f.contact_date, c.id AS cid, c.business_name, c.customer_name FROM followups f "
                              "JOIN customers c ON c.id=f.customer_id WHERE TRIM(f.feedback)<>'' ORDER BY f.id DESC LIMIT 30").fetchall()
        imported = db().execute("SELECT id, business_name, customer_name, feedback FROM customers WHERE TRIM(feedback)<>'' "
                                "ORDER BY updated_at DESC LIMIT 30").fetchall()
        return render_template("report.html", groups=groups, recent=recent, imported=imported)

    # ---------- users ----------
    @app.route("/users", methods=["GET", "POST"])
    @admin_required
    def users():
        if request.method == "POST":
            f = request.form
            if f.get("action") == "toggle" and f.get("id", "").isdigit() and int(f["id"]) != g.user["id"]:
                db().execute("UPDATE users SET active=1-active WHERE id=?", (int(f["id"]),))
                db().commit()
            elif f.get("action") == "create":
                name, email, pw = f.get("name", "").strip(), f.get("email", "").strip().lower(), f.get("password", "")
                if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(pw) < 10:
                    flash("Enter a name, a valid email and a password of at least 10 characters.", "error")
                else:
                    try:
                        db().execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
                                     (name[:100], email, generate_password_hash(pw), "admin" if f.get("role") == "admin" else "staff"))
                        db().commit()
                        flash("User created.", "ok")
                    except sqlite3.IntegrityError:
                        flash("That email is already registered.", "error")
            return redirect(url_for("users"))
        return render_template("users.html", users=db().execute("SELECT * FROM users ORDER BY name").fetchall())

    # ---------- CLI ----------
    @app.cli.command("create-user")
    @click.option("--name", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--role", type=click.Choice(["admin", "staff"]), default="staff")
    @click.password_option()
    def create_user(name, email, role, password):
        if len(password) < 10:
            raise click.ClickException("Password must be at least 10 characters.")
        c = connect()
        c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
                  (name, email.strip().lower(), generate_password_hash(password), role))
        c.commit()
        click.echo("User created.")

    return app
