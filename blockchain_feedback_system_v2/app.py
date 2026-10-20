import os
import hashlib
import json
import sqlite3
import csv
import io
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from contextlib import contextmanager

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from integrity import (HASH_VERSION, block_hash as versioned_block_hash, canonical_json,
                       payload_hash, merkle_root, merkle_proof, verify_merkle_proof)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.environ.get("FEEDBACK_DATABASE", os.path.join(BASE_DIR, "feedback.db"))
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


@contextmanager
def connect_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def calculate_hash(index, timestamp, data_json, previous_hash):
    payload = {
        "index": index,
        "timestamp": timestamp,
        "data_json": data_json,
        "previous_hash": previous_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student', 'admin')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            data_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comments TEXT NOT NULL,
            created_at TEXT NOT NULL,
            block_id INTEGER NOT NULL UNIQUE,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(block_id) REFERENCES blocks(id)
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER,
            event_type TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        """)
        block_columns = {row["name"] for row in db.execute("PRAGMA table_info(blocks)").fetchall()}
        if "hash_version" not in block_columns:
            db.execute("ALTER TABLE blocks ADD COLUMN hash_version TEXT")
        if "payload_hash" not in block_columns:
            db.execute("ALTER TABLE blocks ADD COLUMN payload_hash TEXT")

        # Create a genesis block once, when the chain is empty.
        row = db.execute("SELECT COUNT(*) AS n FROM blocks").fetchone()
        if row["n"] == 0:
            timestamp = utc_now()
            data_json = json.dumps({"message": "Genesis Block"}, sort_keys=True, separators=(",", ":"))
            block_hash = calculate_hash(0, timestamp, data_json, "0")
            db.execute(
                "INSERT INTO blocks(block_index, timestamp, data_json, previous_hash, block_hash) VALUES(?,?,?,?,?)",
                (0, timestamp, data_json, "0", block_hash),
            )

        # Optional first-run admin creation from environment variables.
        # Set ADMIN_USERNAME and ADMIN_PASSWORD before starting the app.
        admin_username = os.environ.get("ADMIN_USERNAME", "").strip()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if admin_username and admin_password:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                    (admin_username, generate_password_hash(admin_password), "admin", utc_now()),
                )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with connect_db() as db:
        return db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def append_feedback_block(db, feedback_data):
    latest = db.execute(
        "SELECT block_index, block_hash FROM blocks ORDER BY block_index DESC LIMIT 1"
    ).fetchone()
    next_index = latest["block_index"] + 1
    timestamp = utc_now()
    # New payloads exclude account identity; this local ledger remains controlled
    # by the same database administrator as the application.
    feedback_data.pop("user_id", None)
    feedback_data.pop("username", None)
    data_json = canonical_json(feedback_data)
    previous_hash = latest["block_hash"]
    digest = hashlib.sha256(data_json.encode("utf-8")).hexdigest()
    current_hash = versioned_block_hash(next_index, timestamp, digest, previous_hash)
    cursor = db.execute(
        "INSERT INTO blocks(block_index, timestamp, data_json, previous_hash, block_hash, hash_version, payload_hash) "
        "VALUES(?,?,?,?,?,?,?)",
        (next_index, timestamp, data_json, previous_hash, current_hash, HASH_VERSION, digest),
    )
    return cursor.lastrowid


def verify_chain(db):
    blocks = db.execute("SELECT * FROM blocks ORDER BY block_index ASC").fetchall()
    if not blocks:
        return False, "No blocks found."
    if blocks[0]["block_index"] != 0 or blocks[0]["previous_hash"] != "0":
        return False, "Genesis block is invalid."
    for position, block in enumerate(blocks):
        if block["block_index"] != position:
            return False, f"Unexpected block index at position {position}."
        version = block["hash_version"] if "hash_version" in block.keys() else None
        if version == HASH_VERSION:
            digest = hashlib.sha256(block["data_json"].encode("utf-8")).hexdigest()
            if block["payload_hash"] != digest:
                return False, f"Payload hash mismatch in block #{block['block_index']}."
            expected = versioned_block_hash(block["block_index"], block["timestamp"], digest,
                                            block["previous_hash"], version)
        elif version is None:
            expected = calculate_hash(block["block_index"], block["timestamp"],
                                      block["data_json"], block["previous_hash"])
        else:
            return False, f"Unsupported hash format in block #{block['block_index']}."
        if expected != block["block_hash"]:
            return False, f"Hash mismatch in block #{block['block_index']}."
        if position > 0 and block["previous_hash"] != blocks[position - 1]["block_hash"]:
            return False, f"Previous-hash mismatch in block #{block['block_index']}."
        if position > 0:
            try:
                payload = json.loads(block["data_json"])
                linked = db.execute("SELECT category, rating, comments FROM feedback WHERE block_id = ?",
                                    (block["id"],)).fetchone()
                if linked and any(payload.get(key) != linked[key]
                                  for key in ("category", "rating", "comments")):
                    return False, f"Feedback payload mismatch in block #{block['block_index']}."
            except (ValueError, TypeError):
                return False, f"Invalid payload in block #{block['block_index']} ."
    return True, f"All {len(blocks)} blocks verified."


@app.context_processor
def inject_user():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"logged_in_user": current_user(), "csrf_token": session["csrf_token"]}


@app.before_request
def csrf_protection():
    if request.method == "POST":
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            abort(400)


@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    user = current_user()
    if user and user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("student_dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(username) < 3 or len(username) > 40:
            flash("Username must be between 3 and 40 characters.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                with connect_db() as db:
                    db.execute(
                        "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                        (username, generate_password_hash(password), "student", utc_now()),
                    )
                flash("Registration successful. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already registered.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as db:
            attempt = db.execute("SELECT * FROM login_attempts WHERE username = ?", (username,)).fetchone()
            if attempt and attempt["locked_until"] and attempt["locked_until"] > utc_now():
                flash("Unable to log in right now. Please try again in a few minutes.", "error")
                return render_template("login.html"), 429
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            with connect_db() as db:
                db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            with connect_db() as db:
                db.execute("INSERT INTO audit_events(actor_id,event_type,created_at) VALUES(?,?,?)",
                           (user["id"], "login", utc_now()))
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        with connect_db() as db:
            db.execute("INSERT INTO login_attempts(username,failures,locked_until) VALUES(?,?,?) "
                       "ON CONFLICT(username) DO UPDATE SET failures=failures+1, "
                       "locked_until=CASE WHEN failures+1 >= 5 THEN ? ELSE locked_until END",
                       (username, 1, None, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/student", methods=["GET", "POST"])
@login_required
def student_dashboard():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        category = request.form.get("category", "").strip()
        rating = request.form.get("rating", "").strip()
        comments = request.form.get("comments", "").strip()
        allowed_categories = {"Teaching", "Course / Subject", "College Facilities", "Library", "Other"}

        if category not in allowed_categories:
            flash("Please select a valid feedback category.", "error")
        elif rating not in {"1", "2", "3", "4", "5"}:
            flash("Please select a rating from 1 to 5.", "error")
        elif not comments or len(comments) > 2000:
            flash("Comments are required and must be 2,000 characters or fewer.", "error")
        else:
            try:
                with connect_db() as db:
                    feedback_data = {
                        "user_id": user["id"],
                        "username": user["username"],
                        "category": category,
                        "rating": int(rating),
                        "comments": comments,
                    }
                    block_id = append_feedback_block(db, feedback_data)
                    db.execute(
                        """INSERT INTO feedback(user_id, category, rating, comments, created_at, block_id)
                           VALUES(?,?,?,?,?,?)""",
                        (user["id"], category, int(rating), comments, utc_now(), block_id),
                    )
                flash("Feedback saved to SQLite and added to the hash-linked blockchain.", "success")
                return redirect(url_for("student_dashboard"))
            except sqlite3.Error:
                flash("Could not save feedback. Please try again.", "error")

    with connect_db() as db:
        feedback_rows = db.execute(
            """SELECT f.*, b.block_index, b.block_hash
               FROM feedback f JOIN blocks b ON b.id = f.block_id
               WHERE f.user_id = ? ORDER BY f.id DESC""",
            (user["id"],),
        ).fetchall()
        valid, verify_message = verify_chain(db)
    return render_template(
        "student.html", feedback_rows=feedback_rows,
        chain_valid=valid, verify_message=verify_message
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    with connect_db() as db:
        total_feedback = db.execute("SELECT COUNT(*) AS n FROM feedback").fetchone()["n"]
        total_students = db.execute("SELECT COUNT(*) AS n FROM users WHERE role='student'").fetchone()["n"]
        avg_rating = db.execute("SELECT AVG(rating) AS avg FROM feedback").fetchone()["avg"]
        category_counts = db.execute(
            "SELECT category, COUNT(*) AS total FROM feedback GROUP BY category ORDER BY total DESC"
        ).fetchall()
        feedback_rows = db.execute(
            """SELECT f.*, b.block_index, b.block_hash, b.previous_hash
               FROM feedback f
               JOIN blocks b ON b.id = f.block_id
               ORDER BY f.id DESC"""
        ).fetchall()
        valid, verify_message = verify_chain(db)
    return render_template(
        "admin.html",
        total_feedback=total_feedback,
        total_students=total_students,
        avg_rating=round(avg_rating, 2) if avg_rating is not None else None,
        category_counts=category_counts,
        feedback_rows=feedback_rows,
        chain_valid=valid,
        verify_message=verify_message,
    )


@app.get("/verify")
@login_required
def verify_endpoint():
    with connect_db() as db:
        valid, message = verify_chain(db)
        count = db.execute("SELECT COUNT(*) AS n FROM blocks").fetchone()["n"]
    return {"valid": valid, "block_count": count, "message": message}


@app.get("/verify/proof/<int:block_index>")
@login_required
def verify_proof(block_index):
    with connect_db() as db:
        rows = db.execute("SELECT block_index, data_json FROM blocks WHERE block_index > 0 ORDER BY block_index").fetchall()
        hashes = [payload_hash(json.loads(row["data_json"])) for row in rows]
        positions = [i for i, row in enumerate(rows) if row["block_index"] == block_index]
        if not positions:
            abort(404)
        position = positions[0]
        root = merkle_root(hashes)
        proof = merkle_proof(hashes, position)
        return {"block_index": block_index, "payload_hash": hashes[position],
                "merkle_root": root, "proof": proof,
                "valid": verify_merkle_proof(hashes[position], proof, root)}


@app.get("/admin/export.csv")
@admin_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Category", "Rating", "Comments", "Submitted UTC", "Block", "Block hash"])
    with connect_db() as db:
        rows = db.execute("SELECT f.category, f.rating, f.comments, f.created_at, b.block_index, b.block_hash "
                          "FROM feedback f JOIN blocks b ON b.id=f.block_id ORDER BY f.id DESC").fetchall()
    for row in rows:
        writer.writerow([row[key] for key in row.keys()])
    response = app.response_class(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=feedback-report.csv"
    return response


@app.get("/admin/audit")
@admin_required
def audit_log():
    with connect_db() as db:
        rows = db.execute("SELECT a.event_type, a.created_at, u.username FROM audit_events a "
                          "LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200").fetchall()
    return render_template("audit.html", audit_rows=rows)


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
    return response


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


init_db()

if __name__ == "__main__":
    # Local development only. Do not use Flask debug mode on a public server.
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"),
            port=int(os.environ.get("FLASK_PORT", "5000")), debug=False)
