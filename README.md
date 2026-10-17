# ServicePro Customer Follow-up Manager

Small-team web app to import trial customers from Excel/CSV, track follow-ups, and report on feedback.

**Stack:** Python 3.12 + Flask, SQLite (WAL) with SQL migrations, server-rendered HTML/CSS (no JS build step), openpyxl/xlrd for Excel, gunicorn.
Chosen because a support team of a few people needs one small, cheap, easy-to-host service; SQLite on a persistent disk is plenty
for tens of thousands of customers. If you later need multiple app servers, move to PostgreSQL (the SQL is plain; adjust `migrations/001_init.sql`).

## Run locally
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app wsgi create-user --role admin      # prompts for name, email, password (min 10 chars)
flask --app wsgi run                           # http://127.0.0.1:5000
python -m unittest discover -s tests -t .      # tests
```
Migrations in `migrations/*.sql` are applied automatically at startup.

## Using it
1. **Import** → upload .xlsx/.xls/.csv → confirm column matching → *Preview* → *Confirm*.
2. Phones are cleaned (spaces, hyphens, brackets, `+91`, `91`, `0`, `0091` prefixes, Excel number formats) to `+91XXXXXXXXXX`.
   Indian numbers must be 10 digits starting 6–9 (landlines are reported as invalid). Other `+country` numbers are kept as `+digits`.
3. A row is skipped if its phone already exists in the database or earlier in the same file; existing data is never changed.
   Invalid rows are skipped too. Every skipped row is stored and downloadable (Excel/CSV) with the reason. Fully blank rows are counted and ignored.
4. Open a customer to edit details and **log follow-ups** (date, method, outcome, feedback, issue type + short issue, next action, next date).
   Logging a follow-up updates last contact, next follow-up and status. “Converted to Paid” sets the paid flag.
5. **Feedback report** groups follow-up issues by type (Problem / Feature request / Objection). Keep issue wording short and consistent.

## Security notes
Login required everywhere (hashed passwords, 12 h sessions, login throttling), CSRF tokens on all POSTs, strict CSP, parameterised SQL,
5 MB / 20,000-row upload limits, extension allow-list, CSV/Excel formula-injection protection on exports, `UNIQUE(phone)` in the database,
admin-only user management and deletion. No public pages show customer data (all pages are `no-store`, `noindex`). Serve only over HTTPS.
Known limits: `.xls` needs `xlrd`; login throttle is per-process (hence one gunicorn worker); back up the database file regularly.

## Deploy (Render, ~10 minutes; any Docker host with a persistent volume works)
1. Push this folder to a private GitHub repo.
2. Render → New → Blueprint → select the repo (uses `render.yaml`: Docker, 1 GB disk at `/data`, generated `SECRET_KEY`).
3. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` when prompted (creates the first admin only if no users exist). After first login, delete `ADMIN_PASSWORD` from the dashboard and add staff under **Team**.
4. Open the Render URL, sign in, and check `/healthz` returns `ok`.
Fly.io/Railway: attach a volume at `/data`, set the env vars from `.env.example`, run the Dockerfile.
**Backups:** copy `/data/servicepro.db` (e.g. Render disk snapshots, or `sqlite3 servicepro.db ".backup backup.db"` on a schedule).
