from flask import Flask, request, jsonify, abort
from werkzeug.exceptions import HTTPException
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
import threading
import math
import random
import string
from datetime import datetime, timedelta, timezone
import ipaddress
import urllib.parse
import urllib.request
import html

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3 MB max request body
# (the profile-picture endpoint allows up to a 2MB image; base64 inflates
# that by ~33% on the wire, so the global cap must be comfortably above 2MB
# or every upload near the documented limit gets rejected before it's even
# read, with a generic 413 instead of the endpoint's own error message)

# ── CORS ───────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://s-high-adavnced-system.vercel.app"
).split(",")

CORS(app,
     origins=ALLOWED_ORIGINS,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "X-Admin-Secret", "X-Device-FP"],
     supports_credentials=False)

# ── CONFIG ──────────────────────────────────────────────────────────────────
DATABASE_URL      = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        "Refusing to start with a guessable default — every login session, "
        "PIN verification, and biometric proof in this app is signed with this secret."
    )
SUPERADMIN_SECRET = os.environ.get("SUPERADMIN_SECRET")
if not SUPERADMIN_SECRET:
    raise RuntimeError(
        "SUPERADMIN_SECRET environment variable is not set. "
        "Refusing to start with a guessable default for an endpoint that can delete any company's account."
    )
BREVO_API_KEY     = os.environ.get("BREVO_API_KEY",     "")
FROM_EMAIL        = os.environ.get("FROM_EMAIL",        "")  # must be a verified sender in your Brevo account
# SMS + WhatsApp (Vonage) — used for the phone/WhatsApp reset code channels.
# Sign up at dashboard.vonage.com to get VONAGE_API_KEY and VONAGE_API_SECRET.
# VONAGE_FROM_NUMBER: the virtual number you buy in the Vonage dashboard
#   (format: digits only, no +, e.g. "447700900000"). Used for SMS.
# VONAGE_WHATSAPP_FROM: your WhatsApp Business number or Vonage sandbox
#   number (format: digits only). For testing use the Vonage sandbox number
#   shown in your dashboard under Messages → Sandbox.
# If any of these are unset, that channel silently falls back to email.
VONAGE_API_KEY        = os.environ.get("VONAGE_API_KEY",        "")
VONAGE_API_SECRET     = os.environ.get("VONAGE_API_SECRET",     "")
VONAGE_FROM_NUMBER    = os.environ.get("VONAGE_FROM_NUMBER",    "")
VONAGE_WHATSAPP_FROM  = os.environ.get("VONAGE_WHATSAPP_FROM",  "")

# ── Input constraints ──────────────────────────────────────────────────────
MAX_NAME_LEN     = 80
MAX_EMAIL_LEN    = 120
MAX_PHONE_LEN    = 30
MAX_ID_LEN       = 20
MAX_COMPANY_LEN  = 80
MAX_PASSWORD_LEN = 128
PIN_RE           = re.compile(r'^\d{4}$')
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


# ===== PIN proof tokens ======================================================
# Short-lived signed token issued after a PIN (or biometric-in-place-of-PIN)
# check succeeds. Lets the frontend re-authorise a sensitive follow-up action
# (change-password, change-pin, update-profile) without re-sending the raw
# PIN digits — needed because a biometric unlock never produces a PIN string
# to resend. Deliberately short-lived (3 minutes) and single-purpose so it
# can't be reused as a general bearer token.
_PIN_PROOF_TTL = 180

def issue_pin_proof(user_id: int) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "PINPROOF"}).encode())
    payload = _b64url(json.dumps({
        "sub": user_id,
        "purpose": "pin_proof",
        "iat": int(time.time()),
        "exp": int(time.time()) + _PIN_PROOF_TTL
    }).encode())
    sig = _b64url(hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def verify_pin_proof(token: str, user_id: int) -> bool:
    try:
        header, payload, sig = token.split(".")
        expected = _b64url(hmac.new(
            JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected):
            return False
        data = json.loads(_b64url_decode(payload))
        if data.get("purpose") != "pin_proof": return False
        if data.get("sub") != user_id:         return False
        if data.get("exp", 0) < time.time():   return False
        return True
    except (ValueError, KeyError):
        return False


# ===== Password hashing =====================================================
def hash_password(password: str, salt=None) -> str:
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${base64.urlsafe_b64encode(dk).decode()}"

def check_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# ===== Haversine ============================================================
def haversine_m(lat1, lng1, lat2, lng2):
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1-a))


# ===== Input Security ========================================================
# Allowed characters for email (RFC 5321 simplified)
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
# Null byte / control character pattern
_BAD_CHARS_RE = re.compile(r'[\x00--]')

def clean_string(value: str, max_len: int, field: str) -> str:
    """Strip dangerous characters and enforce length."""
    if value is None:
        return None
    value = str(value).strip()
    if _BAD_CHARS_RE.search(value):
        abort(400, description=f"'{field}' contains invalid characters.")
    if len(value) > max_len:
        abort(400, description=f"'{field}' exceeds max length of {max_len}.")
    return value

def validate_email_format(email: str) -> str:
    """Validate email format strictly."""
    email = clean_string(email, MAX_EMAIL_LEN, "email")
    if not email or not _EMAIL_RE.match(email):
        abort(400, description="Invalid email address format.")
    return email.lower()

def get_device_fp() -> str:
    """Extract device fingerprint from request headers (sent by frontend)."""
    fp = request.headers.get("X-Device-FP", "")
    return clean_string(fp, 64, "device_fp") or "unknown"


# ===== Progressive Lockout ===================================================
# Escalation schedule: hours locked per level
_LOCKOUT_HOURS = [12, 24, 24, 24 * 30]   # level 0→1→2→3→4
# Sentinel device_fp used to track an identifier's lockout state regardless of
# device. device_fp comes straight from a client-supplied header with no
# server-side verification — without this, an attacker could bypass lockout
# entirely by sending a different X-Device-FP value on every attempt, since
# each "new device" would otherwise get its own fresh 4-attempt budget.
_GLOBAL_FP = "__global__"

def _get_lockout_record(conn, identifier: str, device_fp: str):
    c = conn.cursor()
    c.execute(
        "SELECT * FROM login_attemps WHERE identifier=%s AND device_fp=%s",
        (identifier, device_fp)
    )
    return c.fetchone()

def check_login_lockout(identifier: str, device_fp: str):
    """Abort 429 if this identifier is locked out, either on this specific
    device or globally (across all devices, including spoofed ones)."""
    conn = get_db()
    c    = conn.cursor()
    now  = datetime.utcnow().isoformat()
    c.execute(
        "SELECT locked_until FROM login_attemps WHERE identifier=%s AND device_fp IN (%s,%s)",
        (identifier, device_fp, _GLOBAL_FP)
    )
    recs = c.fetchall()
    conn.close()
    for rec in recs:
        if rec["locked_until"] and rec["locked_until"] > now:
            unlock = datetime.fromisoformat(rec["locked_until"])
            diff   = unlock - datetime.utcnow()
            hours  = int(diff.total_seconds() // 3600)
            mins   = int((diff.total_seconds() % 3600) // 60)
            raise Exception(f"Account locked. Try again in {hours}h {mins}m.")

def _bump_attempt(identifier: str, device_fp: str) -> int:
    """Increment the failure counter for one (identifier, device_fp) row,
    applying lockout if the threshold is reached. Returns the new count."""
    conn = get_db()
    c    = conn.cursor()
    now  = datetime.utcnow()
    c.execute(
        "SELECT id, attempt_count, locked_until, escalation FROM login_attemps WHERE identifier=%s AND device_fp=%s",
        (identifier, device_fp)
    )
    rec = c.fetchone()

    if not rec:
        c.execute(
            "INSERT INTO login_attemps (identifier, device_fp, attempt_count, last_attempt) VALUES (%s,%s,1,%s)",
            (identifier, device_fp, now.isoformat())
        )
        conn.commit(); conn.close()
        return 1

    new_count  = rec["attempt_count"] + 1
    escalation = rec["escalation"]

    if new_count >= 4:
        # Apply lockout at this escalation level
        hours        = _LOCKOUT_HOURS[min(escalation, len(_LOCKOUT_HOURS)-1)]
        locked_until = (now + timedelta(hours=hours)).isoformat()
        new_escalation = min(escalation + 1, len(_LOCKOUT_HOURS))
        c.execute(
            """UPDATE login_attemps
               SET attempt_count=%s, locked_until=%s, escalation=%s, last_attempt=%s
               WHERE id=%s""",
            (new_count, locked_until, new_escalation, now.isoformat(), rec["id"])
        )
    else:
        c.execute(
            "UPDATE login_attemps SET attempt_count=%s, last_attempt=%s WHERE id=%s",
            (new_count, now.isoformat(), rec["id"])
        )

    conn.commit(); conn.close()
    return new_count

def record_failed_login(identifier: str, device_fp: str):
    """Increment failure count for both this specific device and the
    identifier overall (see _GLOBAL_FP). Returns the higher of the two
    counts, used for "N attempts remaining" messaging."""
    device_count = _bump_attempt(identifier, device_fp)
    global_count = _bump_attempt(identifier, _GLOBAL_FP)
    return max(device_count, global_count)

def record_successful_login(identifier: str, device_fp: str):
    """Reset failure count on successful login, both per-device and global."""
    conn = get_db()
    c    = conn.cursor()
    c.execute(
        """UPDATE login_attemps SET attempt_count=0, locked_until=NULL, last_attempt=%s
           WHERE identifier=%s AND device_fp IN (%s,%s)""",
        (datetime.utcnow().isoformat(), identifier, device_fp, _GLOBAL_FP)
    )
    conn.commit(); conn.close()


# ── PIN lockout (per user_id) ────────────────────────────────────────────────
def check_pin_lockout(user_id: int):
    conn = get_db()
    c    = conn.cursor()
    now  = datetime.utcnow().isoformat()
    c.execute("SELECT attempt_count, locked_until, escalation FROM pin_attempts WHERE user_id=%s", (user_id,))
    rec = c.fetchone()
    conn.close()
    if not rec: return
    if rec["locked_until"] and rec["locked_until"] > now:
        unlock = datetime.fromisoformat(rec["locked_until"])
        diff   = unlock - datetime.utcnow()
        hours  = int(diff.total_seconds() // 3600)
        mins   = int((diff.total_seconds() % 3600) // 60)
        abort(429, description=f"PIN locked. Try again in {hours}h {mins}m.")

def record_failed_pin(user_id: int):
    conn = get_db()
    c    = conn.cursor()
    now  = datetime.utcnow()
    c.execute("SELECT id, attempt_count, escalation FROM pin_attempts WHERE user_id=%s", (user_id,))
    rec = c.fetchone()
    if not rec:
        c.execute(
            "INSERT INTO pin_attempts (user_id, attempt_count, last_attempt) VALUES (%s,1,%s)",
            (user_id, now.isoformat())
        )
        conn.commit(); conn.close(); return
    new_count  = rec["attempt_count"] + 1
    escalation = rec["escalation"]
    locked_until = None
    if new_count >= 4:
        hours        = _LOCKOUT_HOURS[min(escalation, len(_LOCKOUT_HOURS)-1)]
        locked_until = (now + timedelta(hours=hours)).isoformat()
        new_escalation = min(escalation + 1, len(_LOCKOUT_HOURS))
        c.execute(
            "UPDATE pin_attempts SET attempt_count=%s, locked_until=%s, escalation=%s, last_attempt=%s WHERE id=%s",
            (new_count, locked_until, new_escalation, now.isoformat(), rec["id"])
        )
    else:
        c.execute(
            "UPDATE pin_attempts SET attempt_count=%s, last_attempt=%s WHERE id=%s",
            (new_count, now.isoformat(), rec["id"])
        )
    conn.commit(); conn.close()

def record_successful_pin(user_id: int):
    conn = get_db()
    c    = conn.cursor()
    c.execute(
        "UPDATE pin_attempts SET attempt_count=0, locked_until=NULL, last_attempt=%s WHERE user_id=%s",
        (datetime.utcnow().isoformat(), user_id)
    )
    conn.commit(); conn.close()

def require_pin(user_id: int, data: dict):
    """
    Re-verify the admin's PIN server-side for sensitive account actions.
    The frontend gates these flows behind a PIN modal, but that is a UX
    convenience only — without this check, anyone holding a valid JWT
    (stolen, replayed, or just read out of browser storage) could change
    the password/PIN/email with no PIN at all. This closes that gap.
    """
    # A biometric unlock (in place of typing the PIN) has no PIN digits to
    # resend, so it instead forwards the short-lived pin_proof issued at the
    # time of that biometric check. Honour that path first.
    pin_proof = data.get("pin_proof")
    if pin_proof:
        if not verify_pin_proof(pin_proof, user_id):
            abort(403, description="PIN verification expired. Please verify again.")
        return

    pin = clean_string(data.get("pin", ""), 4, "pin")
    if not pin or not PIN_RE.match(pin):
        abort(400, description="'pin' must be exactly 4 digits.")
    check_pin_lockout(user_id)
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT pin FROM users WHERE id=%s", (user_id,))
    user = c.fetchone()
    conn.close()   # always closed — no longer leaks on wrong-PIN path
    if not user or not check_password(pin, user["pin"]):
        record_failed_pin(user_id)
        abort(403, description="Incorrect PIN.")
    record_successful_pin(user_id)


# ===== SSRF / Webhook URL Validation =========================================
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def validate_webhook_url(url: str) -> str:
    """Block SSRF: reject non-HTTPS, private IPs, localhost, and dangerous schemes."""
    if not url:
        abort(400, description="Webhook URL is required.")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        abort(400, description="Webhook URL must use HTTPS.")
    hostname = parsed.hostname or ""
    if not hostname:
        abort(400, description="Webhook URL has no valid hostname.")
    # Block localhost variants
    if hostname in ("localhost", "0.0.0.0", "[::]"):
        abort(400, description="Webhook URL cannot point to localhost.")
    # Block private/internal IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        for net in _PRIVATE_NETS:
            if ip in net:
                abort(400, description="Webhook URL cannot point to a private or internal IP address.")
    except ValueError:
        pass  # Hostname is a domain name, not an IP — allowed
    return url


# ===== Error handler for 429 =================================================
@app.errorhandler(429)
def too_many_requests(e): return jsonify({"error": str(e.description)}), 429


# ===== Email (Brevo) =========================================================
def send_email(to: str, subject: str, html: str) -> bool:
    """Send a transactional email via Brevo's API (free tier: 300/day, no card).
    Requires BREVO_API_KEY and FROM_EMAIL (a sender verified in your Brevo account)."""
    if not BREVO_API_KEY:
        print("[EMAIL] ERROR: BREVO_API_KEY is not set.", flush=True)
        return False
    if not FROM_EMAIL:
        print("[EMAIL] ERROR: FROM_EMAIL is not set.", flush=True)
        return False
    try:
        payload = json.dumps({
            "sender":      {"email": FROM_EMAIL},
            "to":          [{"email": to}],
            "subject":     subject,
            "htmlContent": html,
        }).encode()
        req = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept":       "application/json",
                "api-key":      BREVO_API_KEY,
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = 200 <= resp.status < 300
            print(f"[EMAIL] {'Sent' if ok else 'Failed'} to {to} — status {resp.status}", flush=True)
            return ok
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[EMAIL] HTTP {e.code}: {body}", flush=True)
        return False
    except Exception as e:
        print(f"[EMAIL] ERROR sending to {to}: {e}", flush=True)
        return False


# ===== SMS / WhatsApp (Vonage) ===============================================
def send_sms(to: str, message: str) -> bool:
    """Send a plain-text SMS via Vonage's SMS REST API.
    Requires VONAGE_API_KEY, VONAGE_API_SECRET and VONAGE_FROM_NUMBER."""
    if not (VONAGE_API_KEY and VONAGE_API_SECRET and VONAGE_FROM_NUMBER):
        print("[SMS] ERROR: Vonage credentials are not fully set.", flush=True)
        return False
    try:
        payload = urllib.parse.urlencode({
            "api_key":    VONAGE_API_KEY,
            "api_secret": VONAGE_API_SECRET,
            "from":       VONAGE_FROM_NUMBER,
            "to":         to.lstrip("+"),   # Vonage expects digits only, no +
            "text":       message,
            "type":       "text",
        }).encode()
        req = urllib.request.Request(
            "https://rest.nexmo.com/sms/json",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            msgs   = result.get("messages", [])
            ok     = bool(msgs) and msgs[0].get("status") == "0"
            if not ok:
                print(f"[SMS] Vonage error: {msgs[0].get('error-text', 'unknown')}", flush=True)
            else:
                print(f"[SMS] Sent to {to}", flush=True)
            return ok
    except Exception as e:
        print(f"[SMS] ERROR: {e}", flush=True)
        return False


def send_whatsapp(to: str, message: str) -> bool:
    """Send a WhatsApp message via Vonage's Messages API.
    Requires VONAGE_API_KEY, VONAGE_API_SECRET and VONAGE_WHATSAPP_FROM.
    For testing, use the Vonage sandbox (dashboard → Messages → Sandbox)
    and have recipients send the sandbox join keyword first."""
    if not (VONAGE_API_KEY and VONAGE_API_SECRET and VONAGE_WHATSAPP_FROM):
        print("[WHATSAPP] ERROR: Vonage credentials are not fully set.", flush=True)
        return False
    try:
        # Vonage Messages API uses Basic auth with api_key:api_secret
        creds   = base64.b64encode(
            f"{VONAGE_API_KEY}:{VONAGE_API_SECRET}".encode()
        ).decode()
        payload = json.dumps({
            "from":         VONAGE_WHATSAPP_FROM.lstrip("+"),
            "to":           to.lstrip("+"),
            "channel":      "whatsapp",
            "message_type": "text",
            "text":         message,
        }).encode()
        req = urllib.request.Request(
            "https://api.nexmo.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Accept":        "application/json",
                "Authorization": f"Basic {creds}",
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = 200 <= resp.status < 300
            print(f"[WHATSAPP] {'Sent' if ok else 'Failed'} to {to} — status {resp.status}", flush=True)
            return ok
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[WHATSAPP] HTTP {e.code}: {body}", flush=True)
        return False
    except Exception as e:
        print(f"[WHATSAPP] ERROR: {e}", flush=True)
        return False



# ===== Database =============================================================
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            company         TEXT    NOT NULL,
            email           TEXT    NOT NULL UNIQUE,
            phone           TEXT,
            password        TEXT    NOT NULL,
            pin             TEXT    NOT NULL,
            created_at      TEXT    NOT NULL,
            geofence_lat     DOUBLE PRECISION,
            geofence_lng     DOUBLE PRECISION,
            geofence_radius  INTEGER DEFAULT 200,
            geofence_enabled BOOLEAN DEFAULT FALSE,
            checkin_time         TEXT DEFAULT '09:00',
            checkout_time        TEXT DEFAULT '17:00',
            night_checkin_time   TEXT,
            night_checkout_time  TEXT,
            clockout_enabled     BOOLEAN DEFAULT TRUE,
            night_clockout_enabled BOOLEAN DEFAULT TRUE,
            sound_enabled        BOOLEAN DEFAULT TRUE,
            max_devices          INTEGER DEFAULT 3
        )
    """)

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

    c.execute("""
        CREATE TABLE IF NOT EXISTS external_intergrations (
            id          SERIAL  PRIMARY KEY,
            user_id     INTEGER NOT NULL UNIQUE,
            type        TEXT    NOT NULL,
            config      TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)


    c.execute("""
        CREATE TABLE IF NOT EXISTS notices (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            title      TEXT    NOT NULL,
            body       TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            pinned     BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS notice_reads (
            id         SERIAL PRIMARY KEY,
            notice_id  INTEGER NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
            staff_id   TEXT    NOT NULL,
            read_at    TEXT    NOT NULL,
            UNIQUE (notice_id, staff_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id                  SERIAL PRIMARY KEY,
            user_id             INTEGER NOT NULL,
            role                TEXT    NOT NULL DEFAULT 'admin',
            staff_id            TEXT,
            device_fingerprint  TEXT    NOT NULL,
            device_name         TEXT,
            created_at          TEXT    NOT NULL,
            last_used           TEXT,
            expires_at          TEXT,
            status              TEXT    NOT NULL DEFAULT 'trusted',
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE (user_id, role, staff_id, device_fingerprint)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attemps (
            id              SERIAL PRIMARY KEY,
            identifier      TEXT NOT NULL,
            device_fp       TEXT NOT NULL DEFAULT '',
            attempt_count   INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            escalation      INTEGER NOT NULL DEFAULT 0,
            last_attempt    TEXT,
            UNIQUE (identifier, device_fp)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS pin_attempts (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL UNIQUE,
            attempt_count   INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            escalation      INTEGER NOT NULL DEFAULT 0,
            last_attempt    TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id         SERIAL PRIMARY KEY,
            email      TEXT   NOT NULL,
            role       TEXT   NOT NULL DEFAULT 'admin',
            code       TEXT   NOT NULL,
            expires_at TEXT   NOT NULL,
            used       BOOLEAN DEFAULT FALSE,
            attempts   INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Append-only log used purely for rate-limiting forgot-password requests
    # (separate from password_resets, which gets wiped/replaced on every new
    # request and so can't double as a request history).
    c.execute("""
        CREATE TABLE IF NOT EXISTS reset_requests (
            id           SERIAL PRIMARY KEY,
            identifier   TEXT NOT NULL,
            requested_at TEXT NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_reset_requests_identifier ON reset_requests(identifier)")

    # Migrations for existing tables — each runs and commits independently
    # so a failure on one column doesn't silently prevent the rest from
    # being applied (the old pattern caught exceptions and rolled back but
    # never committed, so successful ALTERs were also never persisted).
    migrations = [
        ("password_resets", "attempts",     "INTEGER NOT NULL DEFAULT 0"),
        ("users", "geofence_lat",    "DOUBLE PRECISION"),
        ("users", "geofence_enabled", "BOOLEAN DEFAULT FALSE"),
        ("users", "geofence_lng",    "DOUBLE PRECISION"),
        ("users", "geofence_radius", "INTEGER DEFAULT 200"),
        ("users", "profile_picture", "TEXT"),
        ("trusted_devices", "staff_id", "TEXT"),
        ("trusted_devices", "status",   "TEXT DEFAULT 'trusted'"),
        ("users", "checkin_time",        "TEXT DEFAULT '09:00'"),
        ("users", "night_checkin_time",   "TEXT"),
        ("users", "night_checkout_time",  "TEXT"),
        ("users", "clockout_enabled",             "BOOLEAN DEFAULT TRUE"),
        ("users", "night_clockout_enabled",        "BOOLEAN DEFAULT TRUE"),
        ("users", "auto_clockout_enabled",         "BOOLEAN DEFAULT FALSE"),
        ("users", "night_auto_clockout_enabled",   "BOOLEAN DEFAULT FALSE"),
        ("users", "sound_enabled",          "BOOLEAN DEFAULT TRUE"),
        ("users", "max_devices",            "INTEGER DEFAULT 3"),
        ("users", "checkout_time",   "TEXT DEFAULT '17:00'"),
        ("attendance", "lat",        "DOUBLE PRECISION"),
        ("attendance", "lng",        "DOUBLE PRECISION"),
        ("attendance", "shift_type", "TEXT"),
        ("users", "pin_biometric_enabled", "BOOLEAN DEFAULT FALSE"),
    ]
    for table, col, definition in migrations:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition}")
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[MIGRATION] Warning: could not add {table}.{col}: {e}", flush=True)

    # Drop old constraints and create a safe partial unique index for admin
    # rows so ON CONFLICT works despite staff_id being NULL.
    # NOTE: we do NOT delete any existing rows — the previous migration that
    # did a DELETE was too aggressive and wiped legitimate trusted devices.
    try:
        c.execute("ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_user_id_role_device_fingerprint_key")
        c.execute("ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_user_role_staff_fp_key")
        conn.commit()
    except Exception:
        conn.rollback()

    try:
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_devices_admin_fp
            ON trusted_devices (user_id, role, device_fingerprint)
            WHERE staff_id IS NULL
        """)
        conn.commit()
        print("[MIGRATION] Partial index for admin device rows OK.", flush=True)
    except Exception as e:
        conn.rollback()
        print(f"[MIGRATION] Warning: partial index: {e}", flush=True)

    # ── CRITICAL FIX: staff device binding ──────────────────────────────────
    # The staff-side INSERT in /devices/verify uses
    # "ON CONFLICT (user_id, role, staff_id, device_fingerprint)", which
    # requires an actual unique index on exactly those columns to exist.
    # The inline UNIQUE(...) in CREATE TABLE only applies if the table is
    # being created fresh — on any pre-existing deployment (i.e. this one)
    # it was never retroactively added. Without it, that INSERT throws an
    # unhandled "no unique or exclusion constraint matching ON CONFLICT"
    # error on every second-or-later staff device, which the frontend was
    # silently swallowing and treating as "allow access" — so staff device
    # binding looked like it simply didn't exist.
    #
    # Dedupe first: months of that failure could have let plain (non-ON
    # CONFLICT) inserts elsewhere create real duplicate rows, and creating a
    # unique index over duplicates fails outright.
    try:
        c.execute("""
            DELETE FROM trusted_devices a USING trusted_devices b
            WHERE a.staff_id IS NOT NULL
              AND a.id < b.id
              AND a.user_id = b.user_id AND a.role = b.role
              AND a.staff_id = b.staff_id AND a.device_fingerprint = b.device_fingerprint
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[MIGRATION] Warning: staff device dedupe: {e}", flush=True)

    try:
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_devices_staff_fp
            ON trusted_devices (user_id, role, staff_id, device_fingerprint)
            WHERE staff_id IS NOT NULL
        """)
        conn.commit()
        print("[MIGRATION] Partial index for staff device rows OK.", flush=True)
    except Exception as e:
        conn.rollback()
        print(f"[MIGRATION] Warning: staff partial index: {e}", flush=True)

    # Drop the incorrectly-spelled duplicate tables that were created by an
    # earlier deployment before table names were corrected. The real tables
    # with actual data use the names in init_db above. These duplicates are
    # empty and safe to drop.
    for ghost_table in ("login_attempts", "external_integrations"):
        try:
            c.execute(f"DROP TABLE IF EXISTS {ghost_table}")
            conn.commit()
            print(f"[MIGRATION] Dropped ghost table '{ghost_table}'.", flush=True)
        except Exception as e:
            conn.rollback()
            print(f"[MIGRATION] Warning: could not drop '{ghost_table}': {e}", flush=True)

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

def compute_lateness_grade(checkin_ts: datetime, expected_time_str: str):
    """
    Returns (status_label, minutes_late) based on actual vs expected check-in time.
    expected_time_str: 'HH:MM' in 24h format
    """
    try:
        h, m = map(int, expected_time_str.split(":"))
        expected = checkin_ts.replace(hour=h, minute=m, second=0, microsecond=0)
        diff_minutes = (checkin_ts - expected).total_seconds() / 60
        if diff_minutes <= 0:
            return "Excellent", int(diff_minutes)
        elif diff_minutes <= 5:
            return "Good", int(diff_minutes)
        elif diff_minutes <= 10:
            return "Fair", int(diff_minutes)
        elif diff_minutes <= 15:
            return "Late", int(diff_minutes)
        else:
            return "Very Late", int(diff_minutes)
    except Exception:
        return "Unknown", 0


# ===== Security Headers =====================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    response.headers["Cross-Origin-Opener-Policy"]   = "same-origin-allow-popups"
    return response


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
@app.errorhandler(502)
def bad_gateway(e):  return jsonify({"error": str(e.description)}), 502
@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error."}), 500


# ===== Auth =================================================================
@app.route("/auth/register", methods=["POST"])
def register():
    data     = require_json()
    company  = clean_string(data.get("company"),  MAX_COMPANY_LEN,  "company")
    email    = validate_email_format(data.get("email", ""))
    phone    = clean_string(data.get("phone"),    MAX_PHONE_LEN,    "phone")
    password = clean_string(data.get("password"), MAX_PASSWORD_LEN, "password")
    pin      = clean_string(data.get("pin"),      4,                "pin")

    if not company:  abort(400, description="'company' is required.")
    if not email:    abort(400, description="'email' is required.")
    if not password: abort(400, description="'password' is required.")
    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters.")
    if not pin or not PIN_RE.match(pin):
        abort(400, description="'pin' must be exactly 4 digits.")

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
    data      = require_json()
    email     = validate_email_format(data.get("email", ""))
    password  = clean_string(data.get("password", ""), MAX_PASSWORD_LEN, "password")
    device_fp = get_device_fp()
    if not email or not password:
        abort(400, description="'email' and 'password' are required.")
    # Check lockout before hitting DB
    try:
        check_login_lockout(email, device_fp)
    except Exception as e:
        abort(429, description=str(e))
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = c.fetchone()
    conn.close()
    if not user or not check_password(password, user["password"]):
        count = record_failed_login(email, device_fp)
        remaining = max(0, 4 - count)
        msg = "Incorrect email or password."
        if remaining > 0:
            msg += f" {remaining} attempt(s) remaining before lockout."
        else:
            msg += " Account locked. Check back after lockout period."
        abort(401, description=msg)
    record_successful_login(email, device_fp)
    token = create_token(user["id"], user["company"], role="admin")
    return jsonify({"token": token, "company": user["company"], "user_id": user["id"], "role": "admin"})


@app.route("/auth/staff-login", methods=["POST"])
def staff_login():
    data      = require_json()
    email     = validate_email_format(data.get("email", ""))
    password  = clean_string(data.get("password", ""), MAX_PASSWORD_LEN, "password")
    device_fp = get_device_fp()
    if not email or not password:
        abort(400, description="'email' and 'password' are required.")
    try:
        check_login_lockout(email, device_fp)
    except Exception as e:
        abort(429, description=str(e))
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT sa.*, s.name, u.company, u.geofence_lat, u.geofence_lng, u.geofence_radius,
               u.geofence_enabled, u.checkin_time, u.checkout_time, u.night_checkin_time, u.night_checkout_time,
               u.clockout_enabled, u.night_clockout_enabled, u.sound_enabled
        FROM staff_accounts sa
        JOIN staff s ON s.id=sa.staff_id AND s.user_id=sa.user_id
        JOIN users u ON u.id=sa.user_id
        WHERE sa.email=%s
    """, (email,))
    acc = c.fetchone()
    conn.close()
    if not acc or not check_password(password, acc["password"]):
        count = record_failed_login(email, device_fp)
        remaining = max(0, 4 - count)
        msg = "Incorrect email or password."
        if remaining > 0:
            msg += f" {remaining} attempt(s) remaining."
        else:
            msg += " Account locked. Check back after lockout period."
        abort(401, description=msg)
    record_successful_login(email, device_fp)
    token = create_token(acc["user_id"], acc["company"], role="staff", staff_id=acc["staff_id"])
    return jsonify({
        "token":    token,
        "company":  acc["company"],
        "staff_id": acc["staff_id"],
        "name":     acc["name"],
        "role":     "staff",
        "geofence": {
            "lat":     acc["geofence_lat"],
            "lng":     acc["geofence_lng"],
            "radius":  acc["geofence_radius"],
            "enabled": acc["geofence_enabled"]
        },
        "schedule": {
            "checkin_time":  acc["checkin_time"]  or "09:00",
            "checkout_time": acc["checkout_time"] or "17:00"
        }
    })


@app.route("/auth/staff-register", methods=["POST"])
def staff_register():
    data       = require_json()
    email      = validate_email_format(data.get("email", ""))
    password   = sanitize(data.get("password"),      MAX_PASSWORD_LEN, "password")
    staff_id   = validate_staff_id(data.get("staff_id"))
    comp_email = validate_email_format(data.get("company_email", ""))

    if not email or not password or not comp_email:
        abort(400, description="email, password and company_email are required.")
    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters.")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, company FROM users WHERE email=%s", (comp_email,))
        company_row = c.fetchone()
        if not company_row:
            abort(404, description="Company account not found.")
        user_id = company_row["id"]
        if not staff_exists(conn, user_id, staff_id):
            abort(404, description="Staff ID not found. Ask your admin to add you first.")
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
    pin     = clean_string(data.get("pin", ""), 4, "pin")
    if not pin or not PIN_RE.match(pin):
        abort(400, description="'pin' must be exactly 4 digits.")
    user_id = current["sub"]
    # Check PIN lockout
    check_pin_lockout(user_id)
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT pin FROM users WHERE id=%s", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user or not check_password(pin, user["pin"]):
        record_failed_pin(user_id)
        conn2 = get_db()
        c2    = conn2.cursor()
        c2.execute("SELECT attempt_count FROM pin_attempts WHERE user_id=%s", (user_id,))
        rec   = c2.fetchone()
        conn2.close()
        count     = rec["attempt_count"] if rec else 1
        remaining = max(0, 4 - count)
        msg = "Incorrect PIN."
        if remaining > 0:
            msg += f" {remaining} attempt(s) remaining."
        else:
            msg += " PIN locked. Check back after lockout period."
        abort(403, description=msg)
    record_successful_pin(user_id)
    return jsonify({"ok": True, "pin_proof": issue_pin_proof(user_id)})


@app.route("/auth/verify-pin-biometric", methods=["POST"])
def verify_pin_biometric():
    """
    Lets an admin authorise a sensitive action with Face ID / Fingerprint
    instead of typing their PIN. Only succeeds if:
      1. The admin has explicitly opted in (pin_biometric_enabled=true),
         which itself required entering the real PIN once to turn on, and
      2. The request is coming from a device already on that admin's
         trusted-devices list.
    A valid JWT alone is never enough — this prevents a stolen token (e.g.
    from a different machine) from bypassing the PIN just because the
    feature happens to be enabled somewhere.
    """
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    user_id = current["sub"]
    check_pin_lockout(user_id)

    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT pin_biometric_enabled FROM users WHERE id=%s", (user_id,))
    user = c.fetchone()
    if not user or not user["pin_biometric_enabled"]:
        conn.close()
        abort(403, description="Biometric PIN replacement isn't enabled for this account.")

    device_fp = get_device_fp()
    c.execute(
        "SELECT id FROM trusted_devices WHERE user_id=%s AND role='admin' AND device_fingerprint=%s AND status='trusted'",
        (user_id, device_fp)
    )
    trusted = c.fetchone()
    conn.close()
    if not trusted:
        abort(403, description="This device isn't trusted. Please enter your PIN instead.")

    record_successful_pin(user_id)
    return jsonify({"ok": True, "pin_proof": issue_pin_proof(user_id)})


@app.route("/auth/pin-biometric-toggle", methods=["PUT"])
def pin_biometric_toggle():
    """Admin enables/disables using Face ID / Fingerprint in place of the PIN.
    Enabling requires the real PIN (proves the admin, not just a stolen JWT,
    is making this change). Disabling never requires the PIN — turning off a
    convenience feature can't reduce security, so no friction is needed."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data    = require_json()
    enabled = bool(data.get("enabled"))
    if enabled:
        require_pin(current["sub"], data)
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET pin_biometric_enabled=%s WHERE id=%s", (enabled, current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "pin_biometric_enabled": enabled})


@app.route("/auth/profile", methods=["GET"])
def get_profile():
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("""SELECT id, company, email, phone, created_at,
                        geofence_lat, geofence_lng, geofence_radius, geofence_enabled,
                        checkin_time, checkout_time, night_checkin_time, night_checkout_time,
                        clockout_enabled, night_clockout_enabled,
                        auto_clockout_enabled, night_auto_clockout_enabled,
                        sound_enabled, max_devices, pin_biometric_enabled
                 FROM users WHERE id=%s""", (current["sub"],))
    user = c.fetchone()
    conn.close()
    if not user:
        abort(404)
    return jsonify(dict(user))


@app.route("/auth/update-profile", methods=["PUT"])
def update_profile():
    """Admin updates their own profile. Requires PIN re-verification."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data    = require_json()
    require_pin(current["sub"], data)
    email   = sanitize(data.get("email"),   MAX_EMAIL_LEN,    "email")
    if email:
        email = validate_email_format(email)
    phone   = sanitize(data.get("phone"),   MAX_PHONE_LEN,    "phone")
    company = sanitize(data.get("company"), MAX_COMPANY_LEN,  "company")

    conn = get_db()
    try:
        c = conn.cursor()
        # Check email not taken by someone else
        if email:
            c.execute("SELECT id FROM users WHERE email=%s AND id!=%s", (email, current["sub"]))
            if c.fetchone():
                abort(409, description="This email is already in use by another account.")
        c.execute(
            "UPDATE users SET email=COALESCE(%s,email), phone=%s, company=COALESCE(%s,company) WHERE id=%s",
            (email, phone, company, current["sub"])
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/auth/change-password", methods=["PUT"])
def change_password():
    """Admin changes their own password. Requires PIN re-verification."""
    current     = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data        = require_json()
    require_pin(current["sub"], data)
    new_password = sanitize(data.get("new_password"), MAX_PASSWORD_LEN, "new_password")
    if not new_password or len(new_password) < 8:
        abort(400, description="Password must be at least 8 characters.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET password=%s WHERE id=%s", (hash_password(new_password), current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/auth/change-pin", methods=["PUT"])
def change_pin():
    """Admin changes their own PIN. Requires the OLD PIN, re-verified server-side."""
    current  = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data     = require_json()
    require_pin(current["sub"], data)
    new_pin  = sanitize(data.get("new_pin"), 4, "new_pin")
    if not new_pin or not PIN_RE.match(new_pin):
        abort(400, description="PIN must be exactly 4 digits.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET pin=%s WHERE id=%s", (hash_password(new_pin), current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Forgot password ──────────────────────────────────────────────────────────
@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    data    = require_json()
    email   = validate_email_format(data.get("email", ""))
    role    = data.get("role", "admin")
    channel = data.get("channel", "email")
    if channel not in ("email", "phone", "whatsapp"):
        abort(400, description="'channel' must be 'email', 'phone', or 'whatsapp'.")

    GENERIC_OK = {"ok": True, "message": "If this account exists, a code has been sent."}

    conn = get_db()
    try:
        c = conn.cursor()

        # Rate-limit: max 3 reset requests per email per hour
        rate_key     = f"{role}:{email}"
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        c.execute(
            "SELECT COUNT(*) AS n FROM reset_requests WHERE identifier=%s AND requested_at>%s",
            (rate_key, one_hour_ago)
        )
        if c.fetchone()["n"] >= 3:
            conn.close()
            abort(429, description="Too many reset requests. Please try again later.")
        c.execute(
            "INSERT INTO reset_requests (identifier, requested_at) VALUES (%s,%s)",
            (rate_key, datetime.utcnow().isoformat())
        )
        c.execute("DELETE FROM reset_requests WHERE requested_at<%s",
                  ((datetime.utcnow() - timedelta(days=1)).isoformat(),))
        conn.commit()

        # Look up account + phone number
        if role == "staff":
            c.execute("""
                SELECT sa.id, st.phone
                FROM   staff_accounts sa
                LEFT JOIN staff st ON st.id=sa.staff_id AND st.user_id=sa.user_id
                WHERE  sa.email=%s
            """, (email,))
        else:
            c.execute("SELECT id, phone FROM users WHERE email=%s", (email,))
        user = c.fetchone()

        if not user:
            return jsonify(GENERIC_OK)

        # Generate 6-digit code
        code    = "".join(random.choices(string.digits, k=6))
        expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

        c.execute("DELETE FROM password_resets WHERE email=%s AND role=%s", (email, role))
        c.execute(
            "INSERT INTO password_resets (email, role, code, expires_at) VALUES (%s,%s,%s,%s)",
            (email, role, code, expires)
        )
        conn.commit()
    except Exception as e:
        print(f"[FORGOT-PASSWORD] ERROR: {e}", flush=True)
        raise
    finally:
        conn.close()

    # Deliver the code via the requested channel
    if channel == "phone" and user.get("phone"):
        send_sms(user["phone"],
                 f"Your S Advanced Attendance reset code is {code}. It expires in 10 minutes.")
    elif channel == "whatsapp" and user.get("phone"):
        send_whatsapp(user["phone"],
                      f"Your S Advanced Attendance reset code is *{code}*. It expires in 10 minutes.")
    else:
        # Email requested, or phone/WhatsApp requested but no number on file
        email_body = f"""
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;
                    background:#0f204a;color:#eef4ff;border-radius:16px">
          <h2 style="color:#3fc1c9;margin-bottom:8px">Password Reset</h2>
          <p style="color:#bfc9e3">Your verification code is:</p>
          <div style="font-size:42px;font-weight:800;letter-spacing:12px;text-align:center;
                      padding:24px;background:rgba(255,255,255,0.08);border-radius:12px;margin:20px 0">
            {code}
          </div>
          <p style="color:#bfc9e3;font-size:13px">This code expires in <strong>10 minutes</strong>.</p>
          <p style="color:#bfc9e3;font-size:13px">If you didn't request this, ignore this email.</p>
        </div>
        """
        send_email(email, "Your Password Reset Code — S Advanced Attendance", email_body)

    return jsonify(GENERIC_OK)


@app.route("/auth/reset-password", methods=["POST"])
def reset_password():
    data         = require_json()
    email        = validate_email_format(data.get("email", ""))
    code         = sanitize(data.get("code"),         10,               "code")
    new_password = sanitize(data.get("new_password"), MAX_PASSWORD_LEN, "new_password")
    role         = data.get("role", "admin")

    if not code or not new_password:
        abort(400, description="code and new_password are required.")
    if len(new_password) < 8:
        abort(400, description="Password must be at least 8 characters.")

    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT id, attempts FROM password_resets
        WHERE email=%s AND role=%s AND used=FALSE AND expires_at > %s
        ORDER BY id DESC LIMIT 1
    """, (email, role, datetime.utcnow().isoformat()))
    pending = c.fetchone()

    # No active (unused, unexpired) code at all for this email — nothing to
    # check the guess against.
    if not pending:
        conn.close()
        abort(400, description="Invalid or expired code.")

    # Cap wrong guesses per active code. A 6-digit code is only 1,000,000
    # possibilities — with no throttle at all, that's brute-forceable in
    # minutes by anyone who knows the email. 5 wrong guesses burns the code
    # entirely, forcing a fresh one (which is itself rate-limited to 3/hour
    # via reset_requests), making brute-force practically infeasible.
    if pending["attempts"] >= 5:
        c.execute("UPDATE password_resets SET used=TRUE WHERE id=%s", (pending["id"],))
        conn.commit(); conn.close()
        abort(429, description="Too many incorrect attempts. Please request a new code.")

    c.execute("""
        SELECT id FROM password_resets
        WHERE id=%s AND code=%s
    """, (pending["id"], code))
    row = c.fetchone()
    if not row:
        c.execute("UPDATE password_resets SET attempts=attempts+1 WHERE id=%s", (pending["id"],))
        conn.commit(); conn.close()
        abort(400, description="Invalid or expired code.")

    hashed = hash_password(new_password)
    if role == "staff":
        c.execute("UPDATE staff_accounts SET password=%s WHERE email=%s", (hashed, email))
    else:
        c.execute("UPDATE users SET password=%s WHERE email=%s", (hashed, email))

    if c.rowcount == 0:
        conn.close()
        abort(404, description="Account not found.")

    c.execute("UPDATE password_resets SET used=TRUE WHERE id=%s", (row["id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Password updated. You can now sign in."})


# ── Geofence config ──────────────────────────────────────────────────────────
@app.route("/settings/geofence", methods=["PUT"])
def set_geofence():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data    = require_json()
    enabled = bool(data.get("enabled", False))
    lat     = data.get("lat")
    lng     = data.get("lng")
    try:
        radius = int(data.get("radius", 200))
    except (TypeError, ValueError):
        abort(400, description="'radius' must be a number.")
    conn = get_db()
    c    = conn.cursor()
    if enabled:
        if lat is None or lng is None:
            abort(400, description="lat and lng are required when enabling geofence.")
        try:
            lat = float(lat); lng = float(lng)
        except (TypeError, ValueError):
            abort(400, description="lat and lng must be numbers.")
        c.execute("""UPDATE users SET geofence_lat=%s, geofence_lng=%s,
                     geofence_radius=%s, geofence_enabled=TRUE WHERE id=%s""",
                  (lat, lng, radius, current["sub"]))
    else:
        c.execute("UPDATE users SET geofence_enabled=FALSE WHERE id=%s", (current["sub"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "enabled": enabled, "lat": lat, "lng": lng, "radius": radius})


# ── Work schedule config ─────────────────────────────────────────────────────
@app.route("/settings/schedule", methods=["PUT"])
def set_schedule():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data          = require_json()
    checkin_time  = sanitize(data.get("checkin_time"),  5, "checkin_time")
    checkout_time = sanitize(data.get("checkout_time"), 5, "checkout_time")
    if not checkin_time or not checkout_time:
        abort(400, description="checkin_time and checkout_time are required.")
    # Validate HH:MM format
    time_re = re.compile(r'^\d{2}:\d{2}$')
    if not time_re.match(checkin_time) or not time_re.match(checkout_time):
        abort(400, description="Times must be in HH:MM format.")
    conn = get_db()
    c    = conn.cursor()
    night_checkin                = sanitize(data.get("night_checkin_time"),  5, "night_checkin_time")
    night_checkout               = sanitize(data.get("night_checkout_time"), 5, "night_checkout_time")
    clockout_enabled             = bool(data.get("clockout_enabled",             True))
    night_clockout_enabled       = bool(data.get("night_clockout_enabled",       True))
    auto_clockout_enabled        = bool(data.get("auto_clockout_enabled",        False))
    night_auto_clockout_enabled  = bool(data.get("night_auto_clockout_enabled",  False))
    sound_enabled                = bool(data.get("sound_enabled",                True))
    max_devices                  = min(5, max(1, int(data.get("max_devices", 3))))
    c.execute("""UPDATE users SET checkin_time=%s, checkout_time=%s,
                 night_checkin_time=%s, night_checkout_time=%s,
                 clockout_enabled=%s, night_clockout_enabled=%s,
                 auto_clockout_enabled=%s, night_auto_clockout_enabled=%s,
                 sound_enabled=%s, max_devices=%s WHERE id=%s""",
              (checkin_time, checkout_time, night_checkin, night_checkout,
               clockout_enabled, night_clockout_enabled,
               auto_clockout_enabled, night_auto_clockout_enabled,
               sound_enabled, max_devices, current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True,
                    "checkin_time": checkin_time, "checkout_time": checkout_time,
                    "night_checkin_time": night_checkin, "night_checkout_time": night_checkout,
                    "clockout_enabled": clockout_enabled, "night_clockout_enabled": night_clockout_enabled,
                    "auto_clockout_enabled": auto_clockout_enabled,
                    "night_auto_clockout_enabled": night_auto_clockout_enabled,
                    "sound_enabled": sound_enabled, "max_devices": max_devices})


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
        c.execute("DELETE FROM attendance      WHERE staff_id=%s AND user_id=%s", (staff_id, current["sub"]))
        c.execute("DELETE FROM staff_accounts  WHERE staff_id=%s AND user_id=%s", (staff_id, current["sub"]))
        c.execute("DELETE FROM trusted_devices WHERE staff_id=%s AND user_id=%s AND role='staff'", (staff_id, current["sub"]))
        c.execute("DELETE FROM staff           WHERE id=%s AND user_id=%s",       (staff_id, current["sub"]))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"Staff '{staff_id}' removed."})


# ===== Attendance ===========================================================
@app.route("/attendance", methods=["GET"])
def list_attendance():
    current = get_current_user()
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
    raw = c.fetchall()
    c2 = conn.cursor()
    c2.execute("SELECT checkin_time FROM users WHERE id=%s", (current["sub"],))
    sched2 = c2.fetchone()
    ci_time = (sched2["checkin_time"] if sched2 else None) or "09:00"
    conn.close()
    results = []
    for r in raw:
        rec = dict(r)
        if rec.get("action") == "check_in":
            ts = datetime.fromisoformat(rec["timestamp"])
            grade_label, _ = compute_lateness_grade(ts, ci_time)
            rec["punctuality_grade"] = grade_label
        else:
            rec["punctuality_grade"] = None
        results.append(rec)
    return jsonify(results)


@app.route("/attendance", methods=["POST"])
def record_attendance():
    current  = get_current_user()
    data     = require_json()

    if current.get("role") == "staff":
        staff_id = current.get("staff_id")
    else:
        staff_id = validate_staff_id(data.get("staff_id"))

    action     = sanitize(data.get("action"), 20, "action")
    lat        = data.get("lat")
    lng        = data.get("lng")
    shift_type = sanitize(data.get("shift"), 10, "shift") if data.get("shift") in ("day", "night") else None

    if action not in VALID_ACTIONS:
        abort(400, description=f"'action' must be one of: {', '.join(VALID_ACTIONS)}.")

    if lat is not None:
        try:
            lat = float(lat)
        except (TypeError, ValueError):
            abort(400, description="'lat' must be a number.")
    if lng is not None:
        try:
            lng = float(lng)
        except (TypeError, ValueError):
            abort(400, description="'lng' must be a number.")

    conn = get_db()
    try:
        c = conn.cursor()
        # Load geofence + schedule
        c.execute("""SELECT geofence_lat, geofence_lng, geofence_radius, geofence_enabled,
                            checkin_time, checkout_time
                     FROM users WHERE id=%s""", (current["sub"],))
        settings = c.fetchone()

        # Geofence check
        if settings and settings.get("geofence_enabled") and settings["geofence_lat"] is not None:
            # TEMPORARY DIAGNOSTIC LOGGING — remove once geofencing is
            # confirmed working. Check Render's log output after a test
            # clock-in/scan to see exactly what the server received.
            print(f"[GEOFENCE-DEBUG] role={current.get('role')} action={action} "
                  f"office=({settings['geofence_lat']},{settings['geofence_lng']}) "
                  f"radius={settings['geofence_radius']} received=({lat},{lng})", flush=True)
            if lat is None or lng is None:
                # BUG FIX: geofencing was silently skipped whenever lat/lng
                # weren't sent (e.g. location permission denied, or the
                # browser hadn't gotten a GPS fix yet) — meaning anyone could
                # bypass geofencing entirely just by not sending a location.
                # Enabled geofencing must fail *closed*, not open.
                if current.get("role") == "admin":
                    if not data.get("force"):
                        return jsonify({
                            "location_warning": True,
                            "distance": None,
                            "allowed":  settings["geofence_radius"],
                            "message":  "No location was provided for this staff member, so geofencing couldn't be verified."
                        }), 200
                    # force=true: admin confirmed — fall through and record
                else:
                    abort(403, description="Location is required to clock in/out. Please enable location services and try again.")
            else:
                dist = haversine_m(
                    settings["geofence_lat"], settings["geofence_lng"],
                    lat, lng
                )
                print(f"[GEOFENCE-DEBUG] computed distance={dist:.1f}m (radius={settings['geofence_radius']}m)", flush=True)
                if dist > settings["geofence_radius"]:
                    if current.get("role") == "admin":
                        # Admins can override the geofence — but only if they
                        # explicitly pass force=true after seeing the warning.
                        # Without it return a warning response so the frontend
                        # can show the "Location mismatch — proceed anyway?" popup.
                        if not data.get("force"):
                            # Don't close conn here — the outer finally handles
                            # it. Closing twice was harmless on psycopg2 directly
                            # but unsafe behind a connection pooler (e.g.
                            # Supabase's PgBouncer), which is the likely cause
                            # of force=true requests failing afterward.
                            return jsonify({
                                "location_warning": True,
                                "distance": int(dist),
                                "allowed":  settings["geofence_radius"],
                                "message":  f"Staff location is {int(dist)}m away from the set location (allowed: {settings['geofence_radius']}m)."
                            }), 200
                        # force=true: admin confirmed — fall through and record
                    else:
                        abort(403, description=f"Unable to {action.replace('_',' ')} due to location mismatch. You are {int(dist)}m away (allowed: {settings['geofence_radius']}m).")

        if not staff_exists(conn, current["sub"], staff_id):
            abort(404, description=f"Staff '{staff_id}' not found.")

        # Prevent duplicate/out-of-order actions (double-tap, replayed
        # request, checking out without ever checking in) AND cap staff to
        # one check-in + one check-out per calendar day total — even if
        # they're assigned to both day and night shifts, it's still just
        # one clock-in and one clock-out for the day, not one per shift.
        c.execute(
            """SELECT action, timestamp FROM attendance WHERE user_id=%s AND staff_id=%s
               ORDER BY timestamp DESC LIMIT 1""",
            (current["sub"], staff_id)
        )
        last = c.fetchone()

        if action == "check_in":
            if last and last["action"] == "check_in":
                abort(409, description="Already checked in. Check out first before checking in again.")
            # No open check-in right now. Make sure today's one allowed
            # cycle hasn't already been used (e.g. they already did their
            # day-shift check-in earlier and are now trying to check in
            # again for a night shift on the same calendar day).
            today_str = datetime.utcnow().date().isoformat()
            c.execute(
                """SELECT 1 FROM attendance WHERE user_id=%s AND staff_id=%s
                   AND action='check_in' AND timestamp LIKE %s LIMIT 1""",
                (current["sub"], staff_id, today_str + "%")
            )
            if c.fetchone():
                abort(409, description="Already clocked in and out for today. Only one check-in/check-out is allowed per day, even across day and night shifts.")
        else:  # check_out
            if not last:
                abort(409, description="Cannot check out before checking in.")
            if last["action"] == "check_out":
                abort(409, description="Already checked out. Check in first before checking out again.")
            # else: there's an open check-in — always allow completing it,
            # regardless of which calendar date the check-out itself lands
            # on (a night shift's check-out can legitimately fall on the
            # day after its check-in).

        timestamp = datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO attendance (user_id, staff_id, action, timestamp, lat, lng, shift_type) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (current["sub"], staff_id, action, timestamp, lat, lng, shift_type)
        )
        conn.commit()
    except HTTPException:
        # Normal abort() calls (404/409/etc) — not a real error, just re-raise
        raise
    except Exception as e:
        conn.rollback()
        print(f"[RECORD-ATTENDANCE] ERROR (staff_id={staff_id}, action={action}, force={data.get('force')}): {e}", flush=True)
        raise
    finally:
        conn.close()
    return jsonify({"message": f"{staff_id} {action}", "timestamp": timestamp}), 201


# ===== Attendance summary ===================================================
@app.route("/attendance/summary", methods=["GET"])
def attendance_summary():
    current   = get_current_user()
    period    = request.args.get("period", "weekly")
    filter_id = request.args.get("staff_id")

    if current.get("role") == "staff":
        filter_id = current.get("staff_id")

    now = datetime.utcnow()
    if period == "daily":
        since = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    elif period == "weekly":
        since = (now - timedelta(days=7)).isoformat()
    elif period == "monthly":
        since = (now - timedelta(days=30)).isoformat()
    elif period == "annual":
        since = (now - timedelta(days=365)).isoformat()
    else:
        since = (now - timedelta(days=7)).isoformat()

    conn = get_db()
    c    = conn.cursor()

    # Get schedule for grading
    c.execute("SELECT checkin_time, checkout_time FROM users WHERE id=%s", (current["sub"],))
    sched = c.fetchone()
    checkin_time  = (sched["checkin_time"]  if sched else None) or "09:00"
    checkout_time = (sched["checkout_time"] if sched else None) or "17:00"

    # Get all staff for absent detection
    c.execute("SELECT id, name FROM staff WHERE user_id=%s", (current["sub"],))
    all_staff = {r["id"]: r["name"] for r in c.fetchall()}

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

    from collections import defaultdict
    staff_map       = {}
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
        lateness_grades = []

        for ev in events:
            ts = datetime.fromisoformat(ev["timestamp"])
            if ev["action"] == "check_in":
                check_in_time = ts
                days_present.add(ts.date().isoformat())
                grade_label, mins_late = compute_lateness_grade(ts, checkin_time)
                lateness_grades.append({"date": ts.date().isoformat(), "grade": grade_label, "minutes_late": mins_late})
            elif ev["action"] == "check_out" and check_in_time:
                dur = (ts - check_in_time).total_seconds()
                total_seconds += dur
                sessions.append({
                    "in":    check_in_time.isoformat(),
                    "out":   ts.isoformat(),
                    "hours": round(dur / 3600, 2)
                })
                check_in_time = None

        total_hours = round(total_seconds / 3600, 2)

        # Overall grade from lateness
        grade_order = {"Excellent": 5, "Good": 4, "Fair": 3, "Late": 2, "Very Late": 1, "Absent": 0}
        if lateness_grades:
            avg_score = sum(grade_order.get(g["grade"], 0) for g in lateness_grades) / len(lateness_grades)
            if avg_score >= 4.5:  overall = "Excellent"
            elif avg_score >= 3.5: overall = "Good"
            elif avg_score >= 2.5: overall = "Fair"
            elif avg_score >= 1.5: overall = "Late"
            else:                  overall = "Very Late"
        else:
            overall = "Absent"

        summaries.append({
            "staff_id":       sid,
            "name":           staff_map.get(sid, sid),
            "total_hours":    total_hours,
            "days_present":   len(days_present),
            "grade":          overall,
            "lateness_log":   lateness_grades,
            "sessions":       sessions,
            "checkin_time":   checkin_time,
            "checkout_time":  checkout_time
        })

    # Add absent staff (only for daily period)
    if period == "daily":
        today_str = now.date().isoformat()
        present_ids = set(events_by_staff.keys())
        if filter_id:
            check_ids = {filter_id} if filter_id in all_staff else set()
        else:
            check_ids = set(all_staff.keys())
        for sid in check_ids - present_ids:
            summaries.append({
                "staff_id":      sid,
                "name":          all_staff.get(sid, sid),
                "total_hours":   0,
                "days_present":  0,
                "grade":         "Absent",
                "lateness_log":  [],
                "sessions":      [],
                "checkin_time":  checkin_time,
                "checkout_time": checkout_time
            })

    summaries.sort(key=lambda x: (x["grade"] != "Absent", x["total_hours"]), reverse=True)
    return jsonify({"period": period, "since": since, "summaries": summaries,
                    "checkin_time": checkin_time, "checkout_time": checkout_time})


# ===== AI Analytics =========================================================
@app.route("/analytics", methods=["GET"])
def analytics():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")

    conn = get_db()
    c    = conn.cursor()

    # Get schedule
    c.execute("SELECT checkin_time, checkout_time FROM users WHERE id=%s", (current["sub"],))
    sched = c.fetchone()
    checkin_time = (sched["checkin_time"] if sched else None) or "09:00"

    now       = datetime.utcnow()
    today     = now.date().isoformat()
    week_ago  = (now - timedelta(days=7)).isoformat()
    month_ago = (now - timedelta(days=30)).isoformat()

    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp LIKE %s",
              (current["sub"], today + "%"))
    today_checkins = c.fetchone()["n"]

    c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp>=%s",
              (current["sub"], week_ago))
    week_checkins = c.fetchone()["n"]

    c.execute("""
        SELECT staff_id, timestamp FROM attendance
        WHERE user_id=%s AND action='check_in' AND timestamp>=%s ORDER BY timestamp
    """, (current["sub"], month_ago))
    ci_rows = c.fetchall()

    # Lateness stats for last 30d
    lateness_counts = {"Excellent": 0, "Good": 0, "Fair": 0, "Late": 0, "Very Late": 0}
    for r in ci_rows:
        ts = datetime.fromisoformat(r["timestamp"])
        grade_label, _ = compute_lateness_grade(ts, checkin_time)
        lateness_counts[grade_label] = lateness_counts.get(grade_label, 0) + 1

    c.execute("""
        SELECT a.staff_id, s.name, COUNT(*) AS sessions
        FROM attendance a
        LEFT JOIN staff s ON s.id=a.staff_id AND s.user_id=a.user_id
        WHERE a.user_id=%s AND a.action='check_in' AND a.timestamp>=%s
        GROUP BY a.staff_id, s.name ORDER BY sessions DESC
    """, (current["sub"], month_ago))
    freq_rows = [dict(r) for r in c.fetchall()]

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

    trend = []
    for i in range(13, -1, -1):
        d = (now - timedelta(days=i)).date().isoformat()
        c.execute("SELECT COUNT(*) AS n FROM attendance WHERE user_id=%s AND action='check_in' AND timestamp LIKE %s",
                  (current["sub"], d + "%"))
        trend.append({"date": d, "checkins": c.fetchone()["n"]})

    conn.close()

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
        "low_attendance":       [r for r in freq_rows if r["sessions"] < 3],
        "lateness_breakdown":   lateness_counts,
        "checkin_time":         checkin_time
    })


# ===== External Integration =================================================
@app.route("/integrations", methods=["GET"])
def get_integration():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT type, config, created_at FROM external_intergrations WHERE user_id=%s", (current["sub"],))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(None)
    cfg = json.loads(row["config"])
    safe_cfg = {k: ("***" if "key" in k.lower() or "secret" in k.lower() or "token" in k.lower() else v)
                for k, v in cfg.items()}
    return jsonify({"type": row["type"], "config": safe_cfg, "created_at": row["created_at"]})


@app.route("/integrations", methods=["POST"])
def save_integration():
    current    = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data       = require_json()
    itype      = sanitize(data.get("type"),   20, "type")
    config_raw = data.get("config", {})
    if not isinstance(config_raw, dict):
        abort(400, description="'config' must be a JSON object.")
    config_str = json.dumps(config_raw)
    created    = datetime.utcnow().isoformat()
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO external_intergrations (user_id, type, config, created_at)
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
    c.execute("DELETE FROM external_intergrations WHERE user_id=%s", (current["sub"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/integrations/push", methods=["POST"])
def push_to_integration():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    import urllib.request, urllib.error
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT type, config FROM external_intergrations WHERE user_id=%s", (current["sub"],))
    row = c.fetchone()
    if not row:
        conn.close()
        abort(404, description="No integration configured.")
    data_to_push = require_json()
    cfg   = json.loads(row["config"])
    itype = row["type"]
    conn.close()

    if itype == "webhook":
        url = cfg.get("url")
        if not url:
            abort(400, description="Webhook URL not set.")
        validate_webhook_url(url)  # Re-validate at push time
        # Sanitize payload — only allow safe scalar values
        safe_payload = {k: v for k, v in data_to_push.items()
                        if isinstance(v, (str, int, float, bool)) or v is None}
        payload = json.dumps(safe_payload).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError as e:
            return jsonify({"error": f"Webhook delivery failed: {e.reason}"}), 502
        return jsonify({"ok": True, "type": "webhook"})

    if itype == "google_sheets":
        url = cfg.get("apps_script_url")
        if not url:
            abort(400, description="Google Apps Script URL not set.")
        validate_webhook_url(url)  # Re-validate at push time
        safe_payload = {k: v for k, v in data_to_push.items()
                        if isinstance(v, (str, int, float, bool)) or v is None}
        payload = json.dumps(safe_payload).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=8)
        except urllib.error.URLError as e:
            return jsonify({"error": f"Google Sheets push failed: {e.reason}"}), 502
        return jsonify({"ok": True, "type": "google_sheets"})

    abort(400, description=f"Unknown integration type: {itype}")


# ===== Reports ==============================================================
@app.route("/reports/attendance", methods=["GET"])
def report_attendance():
    current   = get_current_user()
    date_from = request.args.get("from", (datetime.utcnow() - timedelta(days=30)).date().isoformat())
    date_to   = request.args.get("to",   datetime.utcnow().date().isoformat())
    conn = get_db()
    c    = conn.cursor()
    staff_filter = request.args.get("staff_id")
    if current.get("role") == "staff":
        staff_filter = current.get("staff_id")

    # Fetch schedule so we can compute punctuality grade per record
    c.execute("SELECT checkin_time, night_checkin_time FROM users WHERE id=%s", (current["sub"],))
    sched    = c.fetchone()
    day_ci   = (sched["checkin_time"]       if sched else None) or "09:00"
    night_ci = (sched["night_checkin_time"] if sched else None)

    query = """
        SELECT a.id, a.staff_id, s.name, a.action, a.timestamp, a.lat, a.lng,
               a.shift_type
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
    raw  = c.fetchall()
    conn.close()

    results = []
    for r in raw:
        rec = dict(r)
        if rec.get("action") == "check_in":
            try:
                ts       = datetime.fromisoformat(rec["timestamp"])
                shift    = rec.get("shift_type")
                ci_time  = night_ci if (shift == "night" and night_ci) else day_ci
                grade, _ = compute_lateness_grade(ts, ci_time)
                rec["punctuality_grade"] = grade
            except Exception:
                rec["punctuality_grade"] = "Unknown"
        else:
            rec["punctuality_grade"] = None
        results.append(rec)
    return jsonify(results)


# ===== Superadmin ===========================================================
@app.route("/superadmin/stats", methods=["GET"])
def superadmin_stats():
    require_superadmin()
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) AS n FROM users");       total_users      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM staff");       total_staff      = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM attendance");  total_attendance = c.fetchone()["n"]
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
               COUNT(DISTINCT s.id) AS staff_count,
               COUNT(DISTINCT a.id) AS attendance_count
        FROM users u
        LEFT JOIN staff s ON s.user_id=u.id
        LEFT JOIN attendance a ON a.user_id=u.id
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
        c.execute("SELECT id, email FROM users WHERE id=%s", (user_id,))
        user_row = c.fetchone()
        if not user_row:
            abort(404)
        c.execute("DELETE FROM attendance            WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM staff_accounts        WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM staff                 WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM external_intergrations WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM trusted_devices       WHERE user_id=%s", (user_id,))
        c.execute("DELETE FROM pin_attempts          WHERE user_id=%s", (user_id,))
        # Free up the email's lockout history so a future account that
        # re-registers with this same address doesn't inherit a stranger's
        # failed-login lockout state.
        c.execute("DELETE FROM login_attemps WHERE identifier=%s", (user_row["email"],))
        c.execute("DELETE FROM users                 WHERE id=%s",      (user_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"message": f"User {user_id} deleted."})


# ===== Notice Board =========================================================
@app.route("/notices", methods=["GET"])
def get_notices():
    current  = get_current_user()
    staff_id = current.get("staff_id")
    conn = get_db()
    c    = conn.cursor()

    if staff_id:
        # Staff: return all notices with a per-staff read flag
        c.execute("""
            SELECT n.id, n.title, n.body, n.created_at, n.pinned,
                   (r.id IS NOT NULL) AS read
            FROM notices n
            LEFT JOIN notice_reads r
              ON r.notice_id=n.id AND r.staff_id=%s
            WHERE n.user_id=%s
            ORDER BY n.pinned DESC, n.created_at DESC
        """, (staff_id, current["sub"]))
    else:
        # Admin: no read tracking needed
        c.execute("""
            SELECT id, title, body, created_at, pinned, FALSE AS read
            FROM notices WHERE user_id=%s ORDER BY pinned DESC, created_at DESC LIMIT 20
        """, (current["sub"],))

    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/notices/<int:nid>/read", methods=["POST"])
def mark_notice_read(nid):
    """Staff marks a notice as read."""
    current  = get_current_user()
    staff_id = current.get("staff_id")
    if not staff_id:
        abort(403, description="Staff only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO notice_reads (notice_id, staff_id, read_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (notice_id, staff_id) DO NOTHING
    """, (nid, staff_id, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/notices", methods=["POST"])
def post_notice():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data  = require_json()
    title = sanitize(data.get("title"), 120, "title")
    body  = sanitize(data.get("body"),  500, "body")
    pinned = bool(data.get("pinned", False))
    if not title or not body:
        abort(400, description="title and body are required.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO notices (user_id, title, body, created_at, pinned)
        VALUES (%s,%s,%s,%s,%s) RETURNING id
    """, (current["sub"], title, body, datetime.utcnow().isoformat(), pinned))
    nid = c.fetchone()["id"]
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": nid}), 201

@app.route("/notices/<int:nid>", methods=["DELETE"])
def delete_notice(nid):
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("DELETE FROM notices WHERE id=%s AND user_id=%s", (nid, current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ===== Feedback =============================================================
@app.route("/feedback", methods=["POST"])
def submit_feedback():
    current = get_current_user()
    data    = require_json()
    message = sanitize(data.get("message"), 1000, "message")
    rating  = data.get("rating")  # 1-5 optional
    if not message:
        abort(400, description="message is required.")

    role     = current.get("role", "admin")
    sender   = current.get("company") or current.get("staff_id") or "Unknown"
    rating_n = 0
    if rating is not None and str(rating).isdigit():
        rating_n = max(0, min(5, int(rating)))
    stars = "⭐" * rating_n

    safe_sender  = html.escape(str(sender))
    safe_message = html.escape(message)

    html_body = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;
                background:#0f204a;color:#eef4ff;border-radius:16px">
      <h2 style="color:#3fc1c9;margin-bottom:4px">📬 New Feedback</h2>
      <p style="color:#bfc9e3;font-size:13px;margin-bottom:20px">
        S Advanced Attendance System
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <tr><td style="color:#bfc9e3;padding:6px 0;width:120px">From</td>
            <td style="color:#fff;font-weight:700">{safe_sender} ({role})</td></tr>
        {'<tr><td style="color:#bfc9e3;padding:6px 0">Rating</td><td>' + stars + '</td></tr>' if stars else ''}
        <tr><td style="color:#bfc9e3;padding:6px 0;vertical-align:top">Message</td>
            <td style="color:#fff">{safe_message}</td></tr>
        <tr><td style="color:#bfc9e3;padding:6px 0">Time</td>
            <td style="color:#fff">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
      </table>
    </div>
    """
    sent = send_email("ongodsolomon17@gmail.com",
                      f"Feedback from {sender} — S Advanced Attendance", html_body)
    return jsonify({"ok": True, "sent": sent})


# ===== Profile Picture ======================================================
import base64 as _base64

ALLOWED_IMG_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
MAX_IMG_BYTES     = 2 * 1024 * 1024  # 2 MB

@app.route("/settings/profile-picture", methods=["POST"])
def upload_profile_picture():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    data      = require_json()
    mime_type = data.get("mime_type", "")
    img_b64   = data.get("image_b64", "")

    if mime_type not in ALLOWED_IMG_TYPES:
        abort(400, description="Only JPEG, PNG, WebP or GIF images are allowed.")
    try:
        img_bytes = _base64.b64decode(img_b64)
    except Exception:
        abort(400, description="Invalid image data.")
    if len(img_bytes) > MAX_IMG_BYTES:
        abort(400, description="Image must be under 2 MB.")

    # Basic magic-byte validation
    magic = img_bytes[:4]
    valid = (
        magic[:3] == b'\xff\xd8\xff' or   # JPEG
        magic[:4] == b'\x89PNG'       or   # PNG
        magic[:4] == b'RIFF'          or   # WebP (RIFF....WEBP)
        magic[:4] == b'GIF8'               # GIF
    )
    if not valid:
        abort(400, description="File does not appear to be a valid image.")

    # Store as data URL in DB
    data_url = f"data:{mime_type};base64,{img_b64}"
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET profile_picture=%s WHERE id=%s", (data_url, current["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "url": data_url})

@app.route("/settings/profile-picture", methods=["DELETE"])
def delete_profile_picture():
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("UPDATE users SET profile_picture=NULL WHERE id=%s", (current["sub"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/company/branding", methods=["GET"])
def get_company_branding():
    """Public-ish endpoint — staff can fetch their company's branding by user_id."""
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("SELECT company, profile_picture FROM users WHERE id=%s", (current["sub"],))
    row = c.fetchone()
    conn.close()
    if not row:
        abort(404)
    return jsonify(dict(row))


# ===== Device Binding =======================================================
@app.route("/devices", methods=["GET"])
def list_devices():
    """Admin sees their own trusted devices."""
    current = get_current_user()
    conn    = get_db()
    c       = conn.cursor()
    c.execute("""
        SELECT id, device_name, device_fingerprint, created_at, last_used, expires_at, status
        FROM trusted_devices WHERE user_id=%s AND role='admin' ORDER BY last_used DESC
    """, (current["sub"],))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/devices/pending", methods=["GET"])
def list_pending_devices():
    """Admin sees all pending device requests from their staff."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        SELECT td.id, td.device_name, td.device_fingerprint, td.created_at,
               td.staff_id, sa.email as staff_email, s.name as staff_name, td.status
        FROM trusted_devices td
        LEFT JOIN staff_accounts sa ON sa.user_id=td.user_id AND sa.staff_id=td.staff_id
        LEFT JOIN staff s ON s.id=td.staff_id AND s.user_id=td.user_id
        WHERE td.user_id=%s AND td.role='staff' AND td.status='pending'
        ORDER BY td.created_at DESC
    """, (current["sub"],))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/devices/verify", methods=["POST"])
def verify_device():
    """
    Called right after login.
    For admins  : checks trusted_devices for their own fingerprint (no expiry restriction).
    For staff   : checks if this fingerprint is the primary bound device OR
                  an admin-approved temp device still within 20h window.
    Returns {status: 'trusted'|'pending'|'rejected'|'unknown', device_id: int|None}
    """
    current     = get_current_user()
    data        = require_json()
    fingerprint = sanitize(data.get("fingerprint"), 200, "fingerprint")
    device_name = sanitize(data.get("device_name"), 100, "device_name") or "Unknown Device"
    role        = current.get("role", "admin")

    if not fingerprint:
        return jsonify({"status": "unknown"})

    conn = get_db()
    c    = conn.cursor()
    now  = datetime.utcnow().isoformat()

    if role == "admin":
        # Admins: simple trusted check, no expiry
        c.execute("""
            SELECT id, status FROM trusted_devices
            WHERE user_id=%s AND role='admin'
              AND device_fingerprint=%s AND staff_id IS NULL
        """, (current["sub"], fingerprint))
        row = c.fetchone()
        if row and row["status"] == "trusted":
            c.execute("UPDATE trusted_devices SET last_used=%s WHERE id=%s", (now, row["id"]))
            conn.commit()
            conn.close()
            return jsonify({"status": "trusted", "device_id": row["id"]})

        # Device not found or not trusted — check max_devices limit before
        # returning "unknown" (which would show the Trust Device? modal).
        # If limit is reached, block immediately with a clear message.
        c.execute("SELECT max_devices FROM users WHERE id=%s", (current["sub"],))
        u     = c.fetchone()
        max_d = (u["max_devices"] if u else 3) or 3
        c.execute("""
            SELECT COUNT(*) AS n FROM trusted_devices
            WHERE user_id=%s AND role='admin' AND status='trusted'
              AND staff_id IS NULL
        """, (current["sub"],))
        cur_count = c.fetchone()["n"]
        if cur_count >= max_d:
            conn.close()
            return jsonify({
                "status": "rejected",
                "reason": f"Max trusted device limit ({max_d}) reached. Revoke an existing device in Settings first."
            })

        conn.close()
        return jsonify({"status": "unknown"})

    # Staff: find primary bound device (first trusted one) or approved temp
    staff_id = current.get("staff_id")
    c.execute("""
        SELECT id, status, expires_at, device_fingerprint FROM trusted_devices
        WHERE user_id=%s AND role='staff' AND staff_id=%s
        ORDER BY created_at ASC
    """, (current["sub"], staff_id))
    devices = c.fetchall()

    if not devices:
        # First device ever — auto-bind as primary trusted
        c.execute("""
            INSERT INTO trusted_devices
            (user_id, role, staff_id, device_fingerprint, device_name, created_at, last_used, expires_at, status)
            VALUES (%s,'staff',%s,%s,%s,%s,%s,NULL,'trusted')
        """, (current["sub"], staff_id, fingerprint, device_name,
              datetime.utcnow().isoformat(), now))
        conn.commit()
        conn.close()
        return jsonify({"status": "trusted", "first_bind": True})

    # Check if this fingerprint matches any existing device
    for dev in devices:
        if dev["device_fingerprint"] == fingerprint:
            if dev["status"] == "trusted":
                c.execute("UPDATE trusted_devices SET last_used=%s WHERE id=%s", (now, dev["id"]))
                conn.commit()
                conn.close()
                return jsonify({"status": "trusted", "device_id": dev["id"]})
            elif dev["status"] == "approved_temp":
                if dev["expires_at"] and dev["expires_at"] > now:
                    c.execute("UPDATE trusted_devices SET last_used=%s WHERE id=%s", (now, dev["id"]))
                    conn.commit()
                    conn.close()
                    return jsonify({"status": "trusted", "device_id": dev["id"], "temp": True,
                                    "expires_at": dev["expires_at"]})
                else:
                    # Temp approval expired. Fall back to "pending" (instead of
                    # a dead-end "expired" status) so this device reappears in
                    # the admin's Pending Devices queue for a quick re-approval,
                    # rather than disappearing from every admin view forever.
                    c.execute(
                        "UPDATE trusted_devices SET status='pending', created_at=%s WHERE id=%s",
                        (datetime.utcnow().isoformat(), dev["id"])
                    )
                    conn.commit()
                    conn.close()
                    return jsonify({
                        "status": "pending",
                        "reason": "Your temporary access expired. A new approval request has been sent to your admin."
                    })
            elif dev["status"] == "pending":
                conn.close()
                return jsonify({"status": "pending"})
            elif dev["status"] in ("rejected", "expired"):
                conn.close()
                return jsonify({"status": "rejected"})

    # New unknown device for this staff — create a pending request.
    # ON CONFLICT must target the partial index created in init_db
    # (idx_trusted_devices_staff_fp); the WHERE clause has to match exactly
    # for Postgres to use it as the conflict target.
    try:
        c.execute("""
            INSERT INTO trusted_devices
            (user_id, role, staff_id, device_fingerprint, device_name, created_at, last_used, expires_at, status)
            VALUES (%s,'staff',%s,%s,%s,%s,%s,NULL,'pending')
            ON CONFLICT (user_id, role, staff_id, device_fingerprint) WHERE staff_id IS NOT NULL
            DO UPDATE SET status='pending', device_name=EXCLUDED.device_name,
                           created_at=EXCLUDED.created_at, expires_at=NULL
        """, (current["sub"], staff_id, fingerprint, device_name,
              datetime.utcnow().isoformat(), now))
    except Exception:
        # Fallback for the rare case the partial index isn't in place yet
        # on this deployment (e.g. migration hasn't run) — check manually.
        conn.rollback()
        c.execute("""
            SELECT id FROM trusted_devices
            WHERE user_id=%s AND role='staff' AND staff_id=%s AND device_fingerprint=%s
        """, (current["sub"], staff_id, fingerprint))
        existing = c.fetchone()
        if existing:
            c.execute(
                "UPDATE trusted_devices SET status='pending', device_name=%s, created_at=%s, expires_at=NULL WHERE id=%s",
                (device_name, datetime.utcnow().isoformat(), existing["id"])
            )
        else:
            c.execute("""
                INSERT INTO trusted_devices
                (user_id, role, staff_id, device_fingerprint, device_name, created_at, last_used, expires_at, status)
                VALUES (%s,'staff',%s,%s,%s,%s,%s,NULL,'pending')
            """, (current["sub"], staff_id, fingerprint, device_name,
                  datetime.utcnow().isoformat(), now))
    conn.commit()
    conn.close()
    return jsonify({"status": "pending"})


@app.route("/devices/trust", methods=["POST"])
def trust_device():
    """Admin registers their own device as trusted (no expiry)."""
    current     = get_current_user()
    data        = require_json()
    fingerprint = sanitize(data.get("fingerprint"), 200, "fingerprint")
    device_name = sanitize(data.get("device_name"), 100, "device_name") or "Unknown Device"
    if not fingerprint:
        abort(400, description="fingerprint is required.")
    now = datetime.utcnow().isoformat()
    conn = get_db()
    c    = conn.cursor()

    # Check max_devices limit — but exclude the current fingerprint from the
    # count. Re-trusting the same device (e.g. after a revoke/re-add) must
    # not count against the limit, and an ON CONFLICT UPDATE on an existing
    # row doesn't increase the count anyway.
    c.execute("SELECT max_devices FROM users WHERE id=%s", (current["sub"],))
    u     = c.fetchone()
    max_d = u["max_devices"] if u else 3
    c.execute("""
        SELECT COUNT(*) AS n FROM trusted_devices
        WHERE user_id=%s AND role='admin' AND status='trusted'
        AND device_fingerprint != %s
    """, (current["sub"], fingerprint))
    cur_count = c.fetchone()["n"]
    if cur_count >= max_d:
        conn.close()
        abort(400, description=f"Max trusted devices limit ({max_d}) reached. Revoke an existing device first.")

    # Admin rows have staff_id=NULL. Postgres treats NULL!=NULL in UNIQUE
    # constraints, so a plain ON CONFLICT (user_id, role, staff_id,
    # device_fingerprint) would never match an admin row and would insert a
    # duplicate instead of updating. Use a partial index conflict target
    # that only applies to admin rows (WHERE staff_id IS NULL).
    try:
        # Use ON CONFLICT with the partial index (WHERE staff_id IS NULL).
        # This requires idx_trusted_devices_admin_fp to exist (created in init_db).
        c.execute("""
            INSERT INTO trusted_devices
            (user_id, role, staff_id, device_fingerprint, device_name,
             created_at, last_used, expires_at, status)
            VALUES (%s, 'admin', NULL, %s, %s, %s, %s, NULL, 'trusted')
            ON CONFLICT (user_id, role, device_fingerprint)
            WHERE staff_id IS NULL
            DO UPDATE SET last_used=%s, device_name=%s, status='trusted'
        """, (current["sub"], fingerprint, device_name, now, now, now, device_name))
    except Exception:
        # Fallback: partial index may not exist yet on this deployment.
        # Check if a row exists and UPDATE it, otherwise INSERT fresh.
        conn.rollback()
        c = conn.cursor()
        c.execute("""
            SELECT id FROM trusted_devices
            WHERE user_id=%s AND role='admin' AND device_fingerprint=%s
              AND staff_id IS NULL
        """, (current["sub"], fingerprint))
        existing = c.fetchone()
        if existing:
            c.execute("""
                UPDATE trusted_devices SET last_used=%s, device_name=%s, status='trusted'
                WHERE id=%s
            """, (now, device_name, existing["id"]))
        else:
            c.execute("""
                INSERT INTO trusted_devices
                (user_id, role, staff_id, device_fingerprint, device_name,
                 created_at, last_used, expires_at, status)
                VALUES (%s, 'admin', NULL, %s, %s, %s, %s, NULL, 'trusted')
            """, (current["sub"], fingerprint, device_name, now, now))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/devices/<int:device_id>/approve", methods=["POST"])
def approve_device(device_id):
    """Admin approves a pending staff device for 20 hours."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    expires = (datetime.utcnow() + timedelta(hours=20)).isoformat()
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        UPDATE trusted_devices SET status='approved_temp', expires_at=%s
        WHERE id=%s AND user_id=%s AND role='staff'
    """, (expires, device_id, current["sub"]))
    matched = c.rowcount
    conn.commit()
    conn.close()
    if matched == 0:
        abort(404, description="Device request not found.")
    return jsonify({"ok": True, "expires_at": expires})


@app.route("/devices/<int:device_id>/reject", methods=["POST"])
def reject_device(device_id):
    """Admin rejects a pending staff device request."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        UPDATE trusted_devices SET status='rejected'
        WHERE id=%s AND user_id=%s AND role='staff'
    """, (device_id, current["sub"]))
    matched = c.rowcount
    conn.commit()
    conn.close()
    if matched == 0:
        abort(404, description="Device request not found.")
    return jsonify({"ok": True})


@app.route("/devices/<int:device_id>", methods=["DELETE"])
def revoke_device(device_id):
    """Admin revokes any device (their own or staff)."""
    current = get_current_user()
    if current.get("role") != "admin":
        abort(403, description="Admin only.")
    conn    = get_db()
    c       = conn.cursor()
    c.execute("DELETE FROM trusted_devices WHERE id=%s AND user_id=%s",
              (device_id, current["sub"]))
    matched = c.rowcount
    conn.commit()
    conn.close()
    if matched == 0:
        abort(404, description="Device not found.")
    return jsonify({"ok": True})


# ===== Health ===============================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat(), "v": "2.0-brevo-cors"})

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"pong": True})



# ===== Auto Clock-Out Background Job ========================================
def _auto_clockout_worker():
    """
    Runs every 60 seconds. For each company that has auto_clockout_enabled
    or night_auto_clockout_enabled turned on, finds staff who are still
    checked in past their shift's checkout time and inserts a check_out
    record on their behalf.

    Uses UTC time. Since the admin sets checkout_time in local time but
    timestamps are stored in UTC, we compare current UTC hour:minute against
    the stored HH:MM value offset by 0 (UTC+0). If your server and admin
    are both in UTC+1, the relative comparison is still correct because both
    sides are shifted by the same amount. For full multi-timezone support,
    store a tz_offset column — out of scope for now.
    """
    print("[AUTO-CLOCKOUT] Worker started.", flush=True)
    while True:
        try:
            _run_auto_clockout()
        except Exception as e:
            print(f"[AUTO-CLOCKOUT] Error: {e}", flush=True)
        time.sleep(60)


def _run_auto_clockout():
    now     = datetime.utcnow()
    now_str = now.isoformat()
    # Format current time as HH:MM for comparison
    now_hhmm = now.strftime("%H:%M")

    conn = get_db()
    c    = conn.cursor()

    # Load all companies that have at least one auto-clockout enabled
    c.execute("""
        SELECT id, checkout_time, night_checkout_time,
               auto_clockout_enabled, night_auto_clockout_enabled
        FROM users
        WHERE auto_clockout_enabled = TRUE OR night_auto_clockout_enabled = TRUE
    """)
    companies = c.fetchall()

    for co in companies:
        user_id = co["id"]

        # --- Day shift auto clock-out ---
        if co["auto_clockout_enabled"] and co["checkout_time"]:
            if now_hhmm == co["checkout_time"]:
                _clockout_still_in(c, user_id, "day", now_str)

        # --- Night shift auto clock-out ---
        if co["night_auto_clockout_enabled"] and co["night_checkout_time"]:
            if now_hhmm == co["night_checkout_time"]:
                _clockout_still_in(c, user_id, "night", now_str)

    conn.commit()
    conn.close()


def _clockout_still_in(c, user_id: int, shift: str, now_str: str):
    """Insert a system-generated check_out for every staff member who is
    still checked in (last action = check_in) for this company and shift."""
    # Find staff whose most recent attendance record is a check_in
    c.execute("""
        SELECT DISTINCT ON (a.staff_id) a.staff_id, a.action, a.shift_type
        FROM attendance a
        WHERE a.user_id = %s
        ORDER BY a.staff_id, a.timestamp DESC
    """, (user_id,))
    rows = c.fetchall()
    for row in rows:
        if row["action"] != "check_in":
            continue
        # Only auto-clock out if the shift matches (or record has no shift)
        rec_shift = row["shift_type"]
        if rec_shift and rec_shift != shift:
            continue
        c.execute("""
            INSERT INTO attendance (user_id, staff_id, action, timestamp, lat, lng, shift_type)
            VALUES (%s, %s, 'check_out', %s, NULL, NULL, %s)
        """, (user_id, row["staff_id"], now_str, shift))
        print(f"[AUTO-CLOCKOUT] Clocked out {row['staff_id']} (company {user_id}, {shift} shift)", flush=True)


# Start the daemon thread after init_db() has run but before any request
_clockout_thread = threading.Thread(target=_auto_clockout_worker, daemon=True)
_clockout_thread.start()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)