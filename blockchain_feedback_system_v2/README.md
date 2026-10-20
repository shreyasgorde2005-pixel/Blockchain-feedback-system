# Blockchain Feedback System

An educational Flask and SQLite feedback application. It retains the original student registration, login, feedback submission and administration pages, and adds integrity verification, Merkle proofs, CSRF protection, login lockouts, a small audit log and permission-checked CSV export.

## Current architecture

`app.py` contains the Flask routes, SQLite access and role checks. `integrity.py` implements canonical JSON, SHA-256 payload digests and Merkle proofs. Jinja templates render the student and administrator pages. SQLite data is stored in `feedback.db` beside `app.py`.

The schema includes users, feedback, hash-linked blocks, login-attempt state and security audit events. Existing database files are migrated additively when the app starts; the original feedback and blocks are preserved. Passwords use Werkzeug's adaptive password hashing. Public registration only creates student accounts; admin accounts are provisioned from environment variables on startup.

## Windows setup

Open PowerShell in this project folder and run:

```powershell
Copy-Item feedback.db feedback.db.backup
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "Choose-a-long-development-password"
python app.py
```

Open http://127.0.0.1:5000. Keep the same `FLASK_SECRET_KEY` between restarts and set a strong, unique admin password. For each new shell, set these environment variables again. The built-in server is for local demonstration only.

## Docker Compose

Copy `.env.example` to `.env`, set a unique secret and admin password, then run `docker compose up --build`. The app is exposed only on `127.0.0.1:5000`; SQLite persists in the `feedback-data` volume. Protect the `.env` file and the volume backup.

## Routes

- `/register`, `/login`, `/logout` — account lifecycle
- `/student` — submit feedback and view personal submissions
- `/admin` — aggregate dashboard and feedback review (admin only)
- `/admin/export.csv` — controlled CSV export (admin only)
- `/admin/audit` — recent login security events (admin only)
- `/verify` — chain verification JSON for authenticated users
- `/verify/proof/<block-index>` — authenticated Merkle inclusion proof

## Integrity design and demonstration

Each feedback record is canonicalized as sorted compact UTF-8 JSON, hashed with SHA-256, and represented in a block that links to the previous block hash. The chain begins with a genesis block. The integrity page checks sequential indexes, calculated block hashes, previous-hash references, and whether the category, rating and comments in each linked database row still match its ledger payload. Merkle roots and inclusion proofs are computed over feedback payload hashes; proof responses include the root, leaf and sibling path and can be independently checked with `verify_merkle_proof` in `integrity.py`.

To demonstrate, create feedback using a student account, inspect its block hash on the page and open its inclusion-proof link. Then, on a disposable copy of `feedback.db`, alter a feedback comment using a SQLite browser and refresh the administrator page or `/verify`. It should report a payload mismatch. Restore the untouched database copy after the demo. Never tamper with the only copy of project data.

This is a **single-server hash-linked database**, not a decentralized blockchain. It has no consensus, distributed replicas, external timestamp authority or immutable external anchor. A person who can rewrite the database can recompute the chain and Merkle root. Keep protected off-host backups or later add an independently operated anchoring service if stronger evidence is required.

## Security and privacy limitations

The app uses parameterized SQLite queries, adaptive password hashing, CSRF tokens for form posts, generic login errors, five-failure temporary lockouts, role checks, request-size limits and basic security headers. Set HTTPS and secure-cookie configuration at a production reverse proxy, add operational monitoring and use a production WSGI server before deployment.

Admin feedback tables do not show student names. New ledger payloads also omit account identity. The existing relational feedback row retains `user_id`, and older ledger payloads may include identity; therefore the current system does **not** promise anonymous feedback. Do not claim anonymity or use it for sensitive surveys. Anonymity requires redesigning the schema and submission flow to avoid retaining identity-to-response mappings, plus an explicit metadata and retention review.

Email verification, password reset, two-factor authentication, SMTP notifications, survey scheduling/templates, configurable roles beyond student/admin, AI analysis, PDF reports, PostgreSQL migrations, Docker deployment and Ethereum anchoring are not implemented. No AI service or paid service is required or contacted.

## Tests

Run the available unit tests with:

```powershell
python -m unittest discover -s tests -v
```

Tests cover canonical serialization, hash sensitivity and Merkle proofs, including odd-sized batches. The application does not yet have frontend, browser end-to-end or complete security regression suites.

## Backup and restore

Stop the app and copy `feedback.db` to a protected location. Restore by stopping the app and replacing `feedback.db` with the backup. Keep backups outside the project directory and restrict access because the database contains feedback and account-to-feedback mappings.

## Project layout

```text
app.py                 Flask routes, SQLite persistence and permissions
integrity.py           Canonical hashing and Merkle inclusion proofs
templates/             Server-rendered pages
static/style.css       Responsive application styles
tests/                  Integrity unit tests
feedback.db             Local application database (created on first run)
```
