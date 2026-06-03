from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import re
import os
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# ── CORS ───────────────────────────────────────────────────────────────────
CORS(app,
     origins="https://s-high-advanced-system.vercel.app",
     methods=["GET", "POST", "PUT", "DELETE"],
     allow_headers=["Content-Type", "Authorization"])

# ── DATABASE ────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres.axqlgpdincfxbiagzjws:#blueysplash001@aws-0-eu-west-1.pooler.supabase.com:5432/postgres"
)

JWT_SECRET        = os.environ.get("JWT_SECRET",        "change-me-in-production-use-a-long-random-string")
SUPERADMIN_SECRET = os.environ.get("SUPERADMIN_SECRET", "change-this-superadmin-secret")

# ── Input constraints ──────────────────────────────────────────────────────
MAX_NAME_LEN     = 80
MAX_EMAIL_LEN    = 120
MAX_PHONE_LEN    = 30
MAX_ID_LEN       = 20
MAX_COMPANY_LEN  = 80
MAX_PASSWORD_LEN = 128
PIN_RE           = re.compile(r'^\d{4,8}$')
VALID_ACTIONS    = {"check_in", "check_out"}
STAFF_ID_RE      = re.compile(r'^[A-Za-z0-9_\-]+$')


# ===== Simple JWT ===========================================================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))

def create_token(user_id: int, company: str, role: str = "admin", staff_id: str = None) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub":      user_id,
        "company":  company,
        "role":     role,
        "staff_id": staff_id,
        "iat":      int(time.time()),
        "exp":      int(time.time()) + 86400 * 7
    }).encode())
    sig = _b64url(hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token: str) -> dict:
    try:
        header, payload, sig = token.split(".")
        expected = _b64url(hmac.new(
            JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected):
            abort(401, description="Invalid token signature.")
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            abort(401, description="Token expired. Please log in again.")
        return data
    except (ValueError, KeyError):
        abort(401, description="Malformed token.")

def get_current_user() -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, description="Missing or invalid Authorization header.")
    return verify_token(auth[7:])


# ===== Password hashing =====================================================
def hash_password(password: str, salt=None) -> str:
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${base64.urlsafe_b64encode(dk).decode()}"

def check_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# ===== Database =============================================================
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Company admin accounts
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            company    TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            phone      TEXT,
            password   TEXT    NOT NULL,
            pin        TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            geofence_lat   DOUBLE PRECISION,
            geofence_lng   DOUBLE PRECISION,
            geofence_radius INTEGER DEFAULT 200
        )
    """)

    # Staff members (registered by admin)
    c.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            id      TEXT    NOT NULL,
            user_id INTEGER NOT NULL,
            name    TEXT    NOT NULL,
            email   TEXT,
            phone   TEXT,
            PRIMARY KEY (id, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Staff sub-accounts (self-registered by staff)
    c.execute("""
        CREATE TABLE IF NOT EXISTS staff_accounts (
            id           SERIAL  PRIMARY KEY,
            user_id      INTEGER NOT NULL,
            staff_id     TEXT    NOT NULL,
            email        TEXT    NOT NULL UNIQUE,
            password     TEXT    NOT NULL,
            created_at   TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE (user_id, staff_id)
        )
    """)

    # Attendance records
    c.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id        SERIAL PRIMARY KEY,
            user_id   INTEGER NOT NULL,
            staff_id  TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            timestamp TEXT    NOT NULL,
            lat       DOUBLE PRECISION,
            lng       DOUBLE PRECISION,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # External sheet/DB integration config (per company)
    c.execute("""
        CREATE TABLE IF NOT EXISTS external_integrations (
            id          SERIAL  PRIMARY KEY,
            user_id     INTEGER NOT NULL UNIQUE,
            type        TEXT    NOT NULL,
            config      TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Add new columns to existing users table if they don't exist (migration)
    for col, definition in [
        ("geofence_lat",    "DOUBLE PRECISION"),
        ("geofence_lng",    "DOUBLE PRECISION"),
        ("geofence_radius", "INTEGER DEFAULT 200"),
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {definition}")
        except Exception:
            conn.rollback()

    # Add lat/lng to attendance if missing (migration)
    for col, definition in [("lat", "DOUBLE PRECISION"), ("lng", "DOUBLE PRECISION")]:
        try:
            c.execute(f"ALTER TABLE attendance ADD COLUMN IF NOT EXISTS {col} {definition}")
        except Exception:
            conn.rollback()

    conn.commit()
    conn.close()

init_db()


# ===== Helpers ==============================================================
def require_json():
    data = request.get_json(silent=True)
    if data is None:
        abort(400, description="Request body must be valid JSON.")
    return data

def sanitize(value, max_len, field):
    if value is None:
        return None
    value = str(value).strip()
    if len(value) > max_len:
        abort(400, description=f"'{field}' exceeds max length of {max_len}.")
    return value or None

def validate_staff_id(sid):
    if not sid:
        abort(400, description="staff_id is required.")
    sid = str(sid).strip()
    if not STAFF_ID_RE.match(sid) or len(sid) > MAX_ID_LEN:
        abort(400, description="Invalid staff_id format.")
    return sid

def staff_exists(conn, user_id, staff_id):
    c = conn.cursor()
    c.execute("SELECT 1 FROM staff WHERE id=%s AND user_id=%s", (staff_id, user_id))
    return c.fetchone() is not None

def require_superadmin():
    auth = request.headers.get("X-Admin-Secret", "")
    if not hmac.compare_digest(auth, SUPERADMIN_SECRET):
        abort(403, description="Forbidden.")

def haversine_m(lat1, lng1, lat2, lng2):
    """Distance between two lat/lng points in metres."""
    import math
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1-a))


# ===== Error handlers =======================================================
@app.errorhandler(400)
def bad_request(e):  return jsonify({"error": str(e.description)}), 400
@app.errorhandler(401)
def unauthorized(e): return jsonify({"error": str(e.description)}), 401
@app.errorhandler(403)
def forbidden(e):    return jsonify({"error": str(e.description)}), 403
@app.errorhandler(404)
def not_found(e):    return jsonify({"error": "Not found."}), 404
@app.errorhandler(409)
def conflict(e):     return jsonify({"error": str(e.description)}), 409
@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error."}), 500


# ===== Auth =================================================================
@app.route("/auth/register", methods=["POST"])
def register():
    data     = require_json()
    company  = sanitize(data.get("company"),  MAX_COMPANY_LEN,  "company")
    email    = sanitize(data.get("email"),    MAX_EMAIL_LEN,    "email")
    phone    = sanitize(data.get("phone"),    MAX_PHONE_LEN,    "phone")
    password = sanitize(data.get("password"), MAX_PASSWORD_LEN, "password")
    pin      = sanitize(data.get("pin"),      10,               "pin")

    if not company:  abort(400, description="'company' is required.")
    if not email:    abort(400, description="'email' is required.")
    if not password: abort(400, description="'password' is required.")
    if not pin or not PIN_RE.match(pin):
        abort(400, description="'pin' must be 4–8 digits.")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=%s", (email,))
        if c.fetchone():
            abort(409, description="An account with this email already exists.")
        hashed_pw  = hash_password(password)
        hashed_pin = hash_password(pin)
        created    = datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO users (company, email, phone, password, pin, created_at) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
            (company, email, phone, hashed_pw, hashed_pin, created)
        )
        user_id = c.fetchone()["id"]
        conn.commit()
    finally:
        conn.close()
    token = create_token(user_id, company, role="admin")
    return jsonify({"token": token, "company": company, "user_id": user_id, "role": "admin"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data     = require_json()
    email    = sanitize(data.get("email"),    MAX_EMAIL_LEN,    "email")
    password = sanitize(data.get("password"), MAX_PASSWORD_LEN, "password")
    if not email or not password:
        abort(400, description="'email' and 'password' are required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = c.fetchone()
    conn.close()
    if not user or not check_password(password, user["password"]):
        abort(401, description="Incorrect email or password.")
    token = create_token(user["id"], user["company"], role="admin")
    return jsonify({"token": token, "company": user["company"], "user_id": user["id"], "role": "admin"})


# ── Staff sub-account login ─────────────────────────────────────────────────
@app.route("/auth/staff-login", methods=["POST"])
def staff_login():
    """Staff log in with their own email/password to view their own portal."""
    data     = require_json()
    email    = sanitize(data.get("email"),    MAX_EMAIL_LEN,    "email")
    password = sanitize(data.get("password"), MAX_PASSWORD_LEN, "password")
    if not email or not password:
        abort(400, description="'email' and 'password' are required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT sa.*, s.name, u.company, u.geofence_lat, u.geofence_lng, u.geofence_radius
        FROM staff_accounts sa
        JOIN staff s ON s.id=sa.staff_id AND s.user_id=sa.user_id
        JOIN users u ON u.id=sa.user_id
        WHERE sa.email=%s
    """, (email,))
    acc = c.fetchone()
    conn.close()
    if not acc or not check_password(password, acc["password"]):
        abort(401, description="Incorrect email or password.")
    token = create_token(acc["user_id"], acc["company"], role="staff", staff_id=acc["staff_id"])
    return jsonify({
        "token":    token,
        "company":  acc["company"],
        "staff_id": acc["staff_id"],
        "name":     acc["name"],
        "role":     "staff",
        "geofence": {
            "lat":    acc["geofence_lat"],
            "lng":    acc["geofence_lng"],
            "radius": acc["geofence_radius"]
        }
    })


# ── Staff self-register (links to existing staff record by company code + staff ID)
@app.route("/auth/staff-register", methods=["POST"])
def staff_register():
    data      = require_json()
    email     = sanitize(data.get("email"),     MAX_EMAIL_LEN,    "email")
    password  = sanitize(data.get("password"),  MAX_PASSWORD_LEN, "password")
    staff_id  = validate_staff_id(data.get("staff_id"))
    # company_email is the admin account email — used to look up the company
    comp_email = sanitize(data.get("company_email"), MAX_EMAIL_LEN, "company_email")

    if not email or not password or not comp_email:
        abort(400, description="email, password and company_email are required.")
    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters.")

    conn = get_db()
    try:
        c = conn.cursor()
        # Find the company
        c.execute("SELECT id, company FROM users WHERE email=%s", (comp_email,))
        company_row = c.fetchone()
        if not company_row:
            abort(404, description="Company account not found.")
        user_id = company_row["id"]
        # Staff record must already exist
        if not staff_exists(conn, user_id, staff_id):
            abort(404, description="Staff ID not found in this company. Ask your admin to add you first.")
        # Check no duplicate sub-account
        c.execute("SELECT id FROM staff_accounts WHERE user_id=%s AND staff_id=%s", (user_id, staff_id))
        if c.fetchone():
            abort(409, description="A sub-account already exists for this staff ID.")
        c.execute("SELECT id FROM staff_accounts WHERE email=%s", (email,))
        if c.fetchone():
            abort(409, description="This email is already registered.")
        hashed_pw = hash_password(password)
        created   = datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO staff_accounts (user_id, staff_id, email, password, created_at) VALUES (%s,%s,%s,%s,%s)",
            (user_id, staff_id, email, hashed_pw, created)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": "Staff account created. You can now log in."}), 201


@app.route("/auth/verify-pin", methods=["POST"])
def verify_pin():
    current = get_current_user()
    data    = require_json()
    pin     = sanitize(data.get("pin"), 10, "pin")
    if not pin:
        abort(400, description="'pin' is required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT pin FROM users WHERE id=%s", (current["sub"],))
    user = c.fetchone()
    conn.close()
    if not user or not check_password(pin, user["pin"]):
        abort(403, description="Incorrect PIN.")
    return jsonify({"ok": True})


@app.route("/auth/profile", methods=["GET"])
def get_profile():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("SELECT id, company, email, phone, created_at, geofence_lat, geofence_lng, geofence_radius FROM users WHERE id=%s", (current["sub"],))
    user = c.fetchone()
    conn.close()
    if not user:
        abort(404)
    return jsonify(dict(user))


# ── Geofence config ──────────────────────────────────────────────────────────
@app.route("/settings/geofence", methods=["PUT"])
def set_geofence():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data   = require_json()
    lat    = data.get("lat")
    lng    = data.get("lng")
    radius = int(data.get("radius", 200))
    if lat is None or lng is None:
        abort(400, description="lat and lng are required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET geofence_lat=%s, geofence_lng=%s, geofence_radius=%s WHERE id=%s",
              (float(lat), float(lng), radius, current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "lat": lat, "lng": lng, "radius": radius})


# ===== Staff ================================================================
@app.route("/staff", methods=["GET"])
def list_staff():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("SELECT * FROM staff WHERE user_id=%s ORDER BY name", (current["sub"],))
    staff = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in staff])


@app.route("/staff", methods=["POST"])
def add_staff():
    current  = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data     = require_json()
    staff_id = validate_staff_id(data.get("id"))
    name     = sanitize(data.get("name"),  MAX_NAME_LEN,  "name")
    email    = sanitize(data.get("email"), MAX_EMAIL_LEN, "email")
    phone    = sanitize(data.get("phone"), MAX_PHONE_LEN, "phone")
    if not name:
        abort(400, description="'name' is required.")
    conn = get_db()
    try:
        if staff_exists(conn, current["sub"], staff_id):
            abort(409, description=f"Staff ID '{staff_id}' already exists.")
        c = conn.cursor()
        c.execute(
            "INSERT INTO staff (id, user_id, name, email, phone) VALUES (%s,%s,%s,%s,%s)",
            (staff_id, current["sub"], name, email, phone)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{name}' added.", "id": staff_id}), 201


@app.route("/staff/<staff_id>", methods=["PUT"])
def update_staff(staff_id):
    current  = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    staff_id = validate_staff_id(staff_id)
    data     = require_json()
    name     = sanitize(data.get("name"),  MAX_NAME_LEN,  "name")
    email    = sanitize(data.get("email"), MAX_EMAIL_LEN, "email")
    phone    = sanitize(data.get("phone"), MAX_PHONE_LEN, "phone")
    if not name:
        abort(400, description="'name' is required.")
    conn = get_db()
    try:
        if not staff_exists(conn, current["sub"], staff_id):
            abort(404)
        c = conn.cursor()
        c.execute(
            "UPDATE staff SET name=%s, email=%s, phone=%s WHERE id=%s AND user_id=%s",
            (name, email, phone, staff_id, current["sub"])
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{staff_id}' updated."})


@app.route("/staff/<staff_id>", methods=["DELETE"])
def remove_staff(staff_id):
    current  = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    staff_id = validate_staff_id(staff_id)
    conn     = get_db()
    try:
        if not staff_exists(conn, current["sub"], staff_id):
            abort(404)
        c = conn.cursor()
        c.execute("DELETE FROM attendance    WHERE staff_id=%s AND user_id=%s", (staff_id, current["sub"]))
        c.execute("DELETE FROM staff_accounts WHERE staff_id=%s AND user_id=%s", (staff_id, current["sub"]))
        c.execute("DELETE FROM staff         WHERE id=%s AND user_id=%s",        (staff_id, current["sub"]))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{staff_id}' removed."})


# ===== Attendance ===========================================================
@app.route("/attendance", methods=["GET"])
def list_attendance():
    current  = get_current_user()
    # Staff role: only their own records
    if current.get("role") == "staff":
        staff_id = current.get("staff_id")
        conn     = get_db()
        c        = conn.cursor()
        c.execute(
            "SELECT a.*, s.name FROM attendance a "
            "LEFT JOIN staff s ON a.staff_id=s.id AND s.user_id=a.user_id "
            "WHERE a.user_id=%s AND a.staff_id=%s ORDER BY a.timestamp DESC",
            (current["sub"], staff_id)
        )
    else:
        conn = get_db()
        c    = conn.cursor()
        c.execute(
            "SELECT a.*, s.name FROM attendance a "
            "LEFT JOIN staff s ON a.staff_id=s.id AND s.user_id=a.user_id "
            "WHERE a.user_id=%s ORDER BY a.timestamp DESC",
            (current["sub"],)
        )
    records = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in records])


@app.route("/attendance", methods=["POST"])
def record_attendance():
    current  = get_current_user()
    data     = require_json()

    # Staff role can only record for themselves
    if current.get("role") == "staff":
        staff_id = current.get("staff_id")
    else:
        staff_id = validate_staff_id(data.get("staff_id"))

    action   = sanitize(data.get("action"), 20, "action")
    lat      = data.get("lat")
    lng      = data.get("lng")

    if action not in VALID_ACTIONS:
        abort(400, description=f"'action' must be one of: {', '.join(VALID_ACTIONS)}.")

    # Geofence check if coordinates and fence are set
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT geofence_lat, geofence_lng, geofence_radius FROM users WHERE id=%s", (current["sub"],))
        settings = c.fetchone()
        if settings and settings["geofence_lat"] and lat is not None and lng is not None:
            dist = haversine_m(
                settings["geofence_lat"], settings["geofence_lng"],
                float(lat), float(lng)
            )
            if dist > settings["geofence_radius"]:
                abort(403, description=f"You are {int(dist)}m from the office — outside the allowed {settings['geofence_radius']}m radius.")

        if not staff_exists(conn, current["sub"], staff_id):
            abort(404, description=f"Staff '{staff_id}' not found.")
        timestamp = datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO attendance (user_id, staff_id, action, timestamp, lat, lng) VALUES (%s,%s,%s,%s,%s,%s)",
            (current["sub"], staff_id, action, timestamp,
             float(lat) if lat is not None else None,
             float(lng) if lng is not None else None)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"{staff_id} {action}", "timestamp": timestamp}), 201


# ===== Attendance summary (weekly/daily) ====================================
@app.route("/attendance/summary", methods=["GET"])
def attendance_summary():
    """
    Returns per-staff weekly hours (for admin dashboard & staff portal).
    ?period=weekly  — last 7 days (default)
    ?period=daily   — today only
    ?staff_id=X     — filter to one staff member
    """
    current  = get_current_user()
    period   = request.args.get("period", "weekly")
    filter_id = request.args.get("staff_id")

    # Staff can only see themselves
    if current.get("role") == "staff":
        filter_id = current.get("staff_id")

    now   = datetime.utcnow()
    if period == "daily":
        since = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    else:
        since = (now - timedelta(days=7)).isoformat()

    conn = get_db()
    c    = conn.cursor()
    query = """
        SELECT a.staff_id, s.name, a.action, a.timestamp
        FROM attendance a
        LEFT JOIN staff s ON s.id=a.staff_id AND s.user_id=a.user_id
        WHERE a.user_id=%s AND a.timestamp >= %s
    """
    params = [current["sub"], since]
    if filter_id:
        query += " AND a.staff_id=%s"
        params.append(filter_id)
    query += " ORDER BY a.staff_id, a.timestamp ASC"
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Compute hours per staff by pairing check_in → check_out
    from collections import defaultdict
    staff_map = {}
    events_by_staff = defaultdict(list)
    for r in rows:
        staff_map[r["staff_id"]] = r["name"] or r["staff_id"]
        events_by_staff[r["staff_id"]].append(r)

    summaries = []
    for sid, events in events_by_staff.items():
        total_seconds = 0
        days_present  = set()
        check_in_time = None
        sessions      = []
        for ev in events:
            ts = datetime.fromisoformat(ev["timestamp"])
            if ev["action"] == "check_in":
                check_in_time = ts
                days_present.add(ts.date().isoformat())
            elif ev["action"] == "check_out" and check_in_time:
                dur = (ts - check_in_time).total_seconds()
                total_seconds += dur
                sessions.append({
                    "in":  check_in_time.isoformat(),
                    "out": ts.isoformat(),
                    "hours": round(dur / 3600, 2)
                })
                check_in_time = None

        total_hours = round(total_seconds / 3600, 2)
        # Grade: based on expected 8h/day × days in period
        days_in_period = 1 if period == "daily" else 5  # Mon–Fri
        expected_hours = days_in_period * 8
        pct = (total_hours / expected_hours * 100) if expected_hours else 0
        if   pct >= 90: grade = "A"
        elif pct >= 75: grade = "B"
        elif pct >= 60: grade = "C"
        elif pct >= 40: grade = "D"
        else:           grade = "F"

        summaries.append({
            "staff_id":     sid,
            "name":         staff_map[sid],
            "total_hours":  total_hours,
            "days_present": len(days_present),
            "grade":        grade,
            "pct":          round(pct, 1),
            "sessions":     sessions
        })

    summaries.sort(key=lambda x: x["total_hours"], reverse=True)
    return jsonify({"period": period, "since": since, "summaries": summaries})


# ===== AI Analytics =========================================================
@app.route("/analytics", methods=["GET"])
def analytics():
    """Basic AI-style analytics — trends, anomalies, top/bottom performers."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")

    conn = get_db()
    c    = conn.cursor()

    now    = datetime.utcnow()
    today  = now.date().isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()
    month_ago = (now - timedelta(days=30)).isoformat()

    # Today check-ins
    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp LIKE %s",
              (current["sub"], today + "%"))
    today_checkins = c.fetchone()["n"]

    # This week
    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp>=%s",
              (current["sub"], week_ago))
    week_checkins = c.fetchone()["n"]

    # Avg check-in time (last 30d)
    c.execute("""
        SELECT staff_id, timestamp FROM attendance
        WHERE user_id=%s AND action='check_in' AND timestamp>=%s
        ORDER BY timestamp
    """, (current["sub"], month_ago))
    ci_rows = c.fetchall()

    # Staff attendance frequency (last 30d)
    c.execute("""
        SELECT a.staff_id, s.name, COUNT(*) AS sessions
        FROM attendance a
        LEFT JOIN staff s ON s.id=a.staff_id AND s.user_id=a.user_id
        WHERE a.user_id=%s AND a.action='check_in' AND a.timestamp>=%s
        GROUP BY a.staff_id, s.name
        ORDER BY sessions DESC
    """, (current["sub"], month_ago))
    freq_rows = [dict(r) for r in c.fetchall()]

    # Anomaly: staff who checked in but never out today
    c.execute("""
        SELECT DISTINCT a.staff_id, s.name
        FROM attendance a
        LEFT JOIN staff s ON s.id=a.staff_id AND s.user_id=a.user_id
        WHERE a.user_id=%s AND a.action='check_in' AND a.timestamp LIKE %s
        AND NOT EXISTS (
            SELECT 1 FROM attendance b
            WHERE b.user_id=a.user_id AND b.staff_id=a.staff_id
            AND b.action='check_out' AND b.timestamp LIKE %s
        )
    """, (current["sub"], today + "%", today + "%"))
    still_in = [dict(r) for r in c.fetchall()]

    # Daily trend for last 14 days
    trend = []
    for i in range(13, -1, -1):
        d = (now - timedelta(days=i)).date().isoformat()
        c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp LIKE %s",
                  (current["sub"], d + "%"))
        trend.append({"date": d, "checkins": c.fetchone()["n"]})

    conn.close()

    # Avg check-in hour
    if ci_rows:
        hours = [datetime.fromisoformat(r["timestamp"]).hour + datetime.fromisoformat(r["timestamp"]).minute/60
                 for r in ci_rows]
        avg_h = round(sum(hours)/len(hours), 2)
    else:
        avg_h = None

    return jsonify({
        "today_checkins":       today_checkins,
        "week_checkins":        week_checkins,
        "avg_checkin_hour":     avg_h,
        "attendance_frequency": freq_rows,
        "still_clocked_in":     still_in,
        "daily_trend":          trend,
        "top_performers":       freq_rows[:3],
        "low_attendance":       [r for r in freq_rows if r["sessions"] < 3]
    })


# ===== External Integration (Google Sheets / Webhook) =======================
@app.route("/integrations", methods=["GET"])
def get_integration():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT type, config, created_at FROM external_integrations WHERE user_id=%s", (current["sub"],))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(None)
    cfg = json.loads(row["config"])
    # Redact sensitive keys
    safe_cfg = {k: ("***" if "key" in k.lower() or "secret" in k.lower() or "token" in k.lower() else v)
                for k, v in cfg.items()}
    return jsonify({"type": row["type"], "config": safe_cfg, "created_at": row["created_at"]})


@app.route("/integrations", methods=["POST"])
def save_integration():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data        = require_json()
    itype       = sanitize(data.get("type"),   20, "type")
    config_raw  = data.get("config", {})
    if not isinstance(config_raw, dict):
        abort(400, description="'config' must be a JSON object.")
    config_str  = json.dumps(config_raw)
    created     = datetime.utcnow().isoformat()
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO external_integrations (user_id, type, config, created_at)
        VALUES (%s,%s,%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET type=EXCLUDED.type, config=EXCLUDED.config, created_at=EXCLUDED.created_at
    """, (current["sub"], itype, config_str, created))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "type": itype})


@app.route("/integrations", methods=["DELETE"])
def delete_integration():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("DELETE FROM external_integrations WHERE user_id=%s", (current["sub"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/integrations/push", methods=["POST"])
def push_to_integration():
    """Push a single attendance record to external integration (webhook/Google Sheets)."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    import urllib.request, urllib.error

    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT type, config FROM external_integrations WHERE user_id=%s", (current["sub"],))
    row = c.fetchone()
    if not row:
        conn.close()
        abort(404, description="No integration configured.")

    data_to_push = require_json()
    cfg  = json.loads(row["config"])
    itype = row["type"]
    conn.close()

    if itype == "webhook":
        url = cfg.get("url")
        if not url:
            abort(400, description="Webhook URL not set.")
        payload = json.dumps(data_to_push).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError as e:
            abort(502, description=f"Webhook delivery failed: {e.reason}")
        return jsonify({"ok": True, "type": "webhook"})

    # Google Sheets via Apps Script web app URL
    if itype == "google_sheets":
        url = cfg.get("apps_script_url")
        if not url:
            abort(400, description="Google Apps Script URL not set.")
        payload = json.dumps(data_to_push).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=8)
        except urllib.error.URLError as e:
            abort(502, description=f"Google Sheets push failed: {e.reason}")
        return jsonify({"ok": True, "type": "google_sheets"})

    abort(400, description=f"Unknown integration type: {itype}")


# ===== Reports (export data) ================================================
@app.route("/reports/attendance", methods=["GET"])
def report_attendance():
    """Full attendance export for a date range. ?from=YYYY-MM-DD&to=YYYY-MM-DD"""
    current = get_current_user()
    date_from = request.args.get("from", (datetime.utcnow() - timedelta(days=30)).date().isoformat())
    date_to   = request.args.get("to",   datetime.utcnow().date().isoformat())
    conn = get_db()
    c    = conn.cursor()

    staff_filter = request.args.get("staff_id")
    query = """
        SELECT a.id, a.staff_id, s.name, a.action, a.timestamp, a.lat, a.lng
        FROM attendance a
        LEFT JOIN staff s ON s.id=a.staff_id AND s.user_id=a.user_id
        WHERE a.user_id=%s AND a.timestamp >= %s AND a.timestamp <= %s
    """
    params = [current["sub"], date_from, date_to + "T23:59:59"]
    if staff_filter:
        query += " AND a.staff_id=%s"
        params.append(staff_filter)
    query += " ORDER BY a.timestamp DESC"
    c.execute(query, params)
    records = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(records)


# ===== Superadmin ===========================================================
@app.route("/superadmin/stats", methods=["GET"])
def superadmin_stats():
    require_superadmin()
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) AS n FROM users");        total_users      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM staff");        total_staff      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM attendance");   total_attendance = c.fetchone()["n"]
    today = datetime.utcnow().date().isoformat()
    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE action='check_in' AND timestamp LIKE %s", (today + "%",))
    today_checkins = c.fetchone()["n"]
    c.execute("SELECT company, email, created_at FROM users ORDER BY created_at DESC LIMIT 1")
    newest_user = c.fetchone()
    conn.close()
    return jsonify({
        "total_users": total_users, "total_staff": total_staff,
        "total_attendance": total_attendance, "today_checkins": today_checkins,
        "newest_user": dict(newest_user) if newest_user else None,
        "server_time": datetime.utcnow().isoformat()
    })

@app.route("/superadmin/users", methods=["GET"])
def superadmin_users():
    require_superadmin()
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT u.id, u.company, u.email, u.phone, u.created_at,
               COUNT(DISTINCT s.id)  AS staff_count,
               COUNT(DISTINCT a.id)  AS attendance_count
        FROM users u
        LEFT JOIN staff      s ON s.user_id = u.id
        LEFT JOIN attendance a ON a.user_id = u.id
        GROUP BY u.id ORDER BY u.created_at DESC
    """)
    users = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in users])

@app.route("/superadmin/users/<int:user_id>", methods=["DELETE"])
def superadmin_delete_user(user_id):
    require_superadmin()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id=%s", (user_id,))
        if not c.fetchone():
            abort(404)
        c.execute("DELETE FROM attendance           WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM staff_accounts       WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM staff                WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM external_integrations WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM users                WHERE id=%s",      (user_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"User {user_id} deleted."})


# ===== Run ==================================================================
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
