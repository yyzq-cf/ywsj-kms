#!/usr/bin/env python3
"""ywsj-kms Web Monitor - KMS activation server with web dashboard"""

import os
import re
import sqlite3
import subprocess
import threading
import time
import hashlib
import secrets
import json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

DB_PATH = os.environ.get("KMS_DB_PATH", "/data/kms.db")
LOG_PATH = os.environ.get("KMS_LOG_PATH", "/data/kms.log")
KMS_PORT = os.environ.get("KMS_PORT", "1688")
WEB_PORT = os.environ.get("WEB_PORT", "8080")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "kms123456")
SECRET_KEY_FILE = os.environ.get("KMS_SECRET_KEY_FILE", "/data/secret_key.txt")

# ── Trusted proxy hop count ──
# When behind nginx, X-Forwarded-For has: client, proxy1, proxy2...
# We take the Nth-from-right entry (0 = rightmost = closest proxy).
# Set TRUSTED_PROXY_HOPS=1 if behind a single nginx, 0 for direct exposure.
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))


def _load_secret_key():
    """Load or generate a persistent secret key."""
    env_key = os.environ.get("KMS_SECRET_KEY")
    if env_key:
        return env_key
    try:
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, 'r') as f:
                key = f.read().strip()
                if key:
                    return key
        key = secrets.token_hex(32)
        os.makedirs(os.path.dirname(SECRET_KEY_FILE) or '.', exist_ok=True)
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)
        return key
    except Exception:
        return secrets.token_hex(32)


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=24*3600,  # 24 hours
    MAX_CONTENT_LENGTH=2 * 1024,  # 2KB limit for JSON POST bodies
)


# ── Brute-force protection ──
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
_login_attempts = {}  # {ip: {"count": N, "first": ts, "locked_until": ts}}
_login_lock = threading.Lock()


def get_client_ip():
    """Get the real client IP, respecting trusted proxy chain.

    If TRUSTED_PROXY_HOPS=0 (direct), always use remote_addr — never trust XFF.
    If TRUSTED_PROXY_HOPS=1 (behind one nginx), take the leftmost XFF entry.
    """
    if TRUSTED_PROXY_HOPS > 0:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            parts = [p.strip() for p in xff.split(",")]
            idx = len(parts) - TRUSTED_PROXY_HOPS
            if 0 <= idx < len(parts):
                return parts[idx]
    return request.remote_addr or "unknown"


def check_rate_limit():
    """Check if IP is locked out. Returns (allowed, remaining, wait_seconds)."""
    ip = get_client_ip()
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip)
        if rec and rec.get("locked_until") and now < rec["locked_until"]:
            wait = int(rec["locked_until"] - now)
            return False, 0, wait
        if rec and now - rec.get("first", now) > LOCKOUT_MINUTES * 60:
            _login_attempts.pop(ip, None)
            rec = None
        return True, MAX_ATTEMPTS - (rec["count"] if rec else 0), 0


def record_failed_attempt():
    """Record a failed login attempt for the client IP."""
    ip = get_client_ip()
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip, {"count": 0, "first": now})
        rec["count"] += 1
        rec["first"] = rec.get("first", now)
        if rec["count"] >= MAX_ATTEMPTS:
            rec["locked_until"] = now + LOCKOUT_MINUTES * 60
            rec["count"] = 0
        _login_attempts[ip] = rec


def clear_attempts():
    """Clear failed attempts on successful login."""
    ip = get_client_ip()
    with _login_lock:
        _login_attempts.pop(ip, None)


# ── API rate limiting ──
_api_limits = {}  # {ip: {"count": N, "window_start": ts}}
_api_lock = threading.Lock()
API_RATE_LIMIT = int(os.environ.get("API_RATE_LIMIT", "60"))  # per minute
API_RATE_WINDOW = 60


def api_rate_limit():
    """Rate limit for authenticated API endpoints. Returns True if allowed."""
    ip = get_client_ip()
    now = time.time()
    with _api_lock:
        rec = _api_limits.get(ip)
        if not rec or now - rec["window_start"] > API_RATE_WINDOW:
            _api_limits[ip] = {"count": 1, "window_start": now}
            return True
        rec["count"] += 1
        if rec["count"] > API_RATE_LIMIT:
            return False
        return True


# ── Security headers ──
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return resp


# ── CSRF protection ──
def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


# Inject CSRF token into all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)


def csrf_protect(f):
    """CSRF protection decorator for POST endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token') or \
                (request.form.get('_csrf_token') if request.form else None) or \
                (request.get_json(silent=True) or {}).get('_csrf_token')
        expected = session.get('_csrf_token')
        if not expected or not token or not secrets.compare_digest(token, expected):
            return jsonify({'ok': False, 'msg': 'CSRF token invalid'}), 403
        return f(*args, **kwargs)
    return decorated


# ── KMS ID/name mappings ──
APP_NAMES = {
    "55c92734-d682-4d71-983e-d6ec3f16059f": "Windows",
    "59a52881-a989-479d-af46-f275c6370663": "Office 2013+",
    "0ff1ce15-a989-479d-af46-f275c6370663": "Office 2010/2019/2021",
}

KMS_ID_NAMES = {
    "58e2134f-8e11-4d17-9cb2-91069c270148": "Windows 10/11 Enterprise LTSC",
    "bbc71f28-4313-4183-9657-8693f559139a": "Windows Server 2025 Datacenter",
    "9c04b35f-aa56-4e7e-91fa-a4de87d2ac96": "Windows Server 2025 Standard",
    "ef6cfc9f-8c5d-44ac-93aa-72ec034eefe6": "Windows Server 2022 Datacenter",
    "7051f0ce-7803-44dc-8760-ae1d8e9729c0": "Windows Server 2022 Standard",
    "9036778e-d09b-4aa8-9ab0-9b1e68268488": "Windows Server 2019 Datacenter",
    "8449b1fb-f0ea-497a-99ab-66ca96e9a0f5": "Windows Server 2019 Essentials",
    "21c8d6dc-5b83-4d0c-af1f-1d4e2e8b0b9e": "Windows Server 2016 Datacenter",
    "f2e4d5c3-b6a7-8d9e-0f1e-2b3c4d5e6f70": "Windows Server 2016 Standard",
}

LICENSE_STATUS = {
    0: "Unlicensed", 1: "Licensed", 2: "OOB grace",
    3: "OOT grace", 4: "Non-genuine grace",
    5: "Notification", 6: "Extended grace",
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS activation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT,
            client_port TEXT,
            protocol_version TEXT,
            is_virtual_machine TEXT,
            license_status TEXT,
            license_status_code INTEGER,
            remaining_time_minutes INTEGER,
            application_id TEXT,
            application_name TEXT,
            sku_id TEXT,
            kms_id TEXT,
            kms_id_name TEXT,
            client_machine_id TEXT,
            previous_client_machine_id TEXT,
            request_timestamp_utc TEXT,
            workstation_name TEXT,
            n_count_policy INTEGER,
            response_epid TEXT,
            active_clients INTEGER,
            renewal_interval INTEGER,
            activation_interval INTEGER,
            raw_log TEXT
        );
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            totp_secret TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_log_ts ON activation_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_log_ip ON activation_logs(client_ip);
        CREATE INDEX IF NOT EXISTS idx_log_ws ON activation_logs(workstation_name);
    """)
    # ── Migration: add totp_secret column if missing (existing DBs) ──
    cols = [r[1] for r in conn.execute("PRAGMA table_info(admin_users)").fetchall()]
    if 'totp_secret' not in cols:
        conn.execute("ALTER TABLE admin_users ADD COLUMN totp_secret TEXT")
        print("Migration: added totp_secret column", flush=True)

    existing = conn.execute(
        "SELECT id FROM admin_users WHERE username=?", (ADMIN_USER,)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?)",
            (ADMIN_USER, generate_password_hash(ADMIN_PASS),
             datetime.now(timezone.utc).isoformat())
        )
    conn.commit()
    conn.close()


# ── Log parser ──
class KMSLogParser:
    RE_CONN_ACCEPT = re.compile(r'IPv4 connection accepted: ([\d.]+):(\d+).')
    RE_CONN_CLOSE = re.compile(r'IPv4 connection closed: ([\d.]+):(\d+).')
    RE_PROTO = re.compile(r'Protocol version\s+: ([\d.]+)')
    RE_VM = re.compile(r'Client is a virtual machine\s+: (\w+)')
    RE_LIC = re.compile(r'Licensing status\s+: (\d+) \(([^)]+)\)')
    RE_REMAIN = re.compile(r'Remaining time.*?: (\d+) minutes')
    RE_APP = re.compile(r'Application ID\s+: ([0-9a-f-]+)')
    RE_SKU = re.compile(r'SKU ID.*?: ([0-9a-f-]+)')
    RE_KMS = re.compile(r'KMS ID.*?: ([0-9a-f-]+)')
    RE_CMID = re.compile(r'Client machine ID\s+: ([0-9a-f-]+)')
    RE_PREV = re.compile(r'Previous client machine ID\s+: ([0-9a-f-]+)')
    RE_REQTS = re.compile(r'Client request timestamp \(UTC\)\s+: (.+)')
    RE_WS = re.compile(r'Workstation name\s+: (.+)')
    RE_NCOUNT = re.compile(r'N count policy.*?: (\d+)')
    RE_EPID = re.compile(r'KMS host extended PID\s+: (.+)')
    RE_ACTIVE = re.compile(r'KMS host current active clients\s+: (\d+)')
    RE_RENEW = re.compile(r'Renewal interval policy\s+: (\d+)')
    RE_ACTINT = re.compile(r'Activation interval policy\s+: (\d+)')

    def __init__(self):
        self.current = None
        self.raw_lines = []

    def parse_line(self, line):
        ts_m = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):', line)
        ts = ts_m.group(1) if ts_m else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = re.sub(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}: ', '', line).strip()
        self.raw_lines.append(line.strip())

        m = self.RE_CONN_ACCEPT.search(clean)
        if m:
            if self.current and self.current.get('application_id'):
                self._save()
            self.current = {'timestamp': ts, 'client_ip': m.group(1), 'client_port': m.group(2)}
            self.raw_lines = [line.strip()]
            return

        if not self.current:
            self.current = {'timestamp': ts}
            self.raw_lines = [line.strip()]

        checks = [
            ('protocol_version', self.RE_PROTO),
            ('is_virtual_machine', self.RE_VM),
            ('remaining_time_minutes', self.RE_REMAIN),
            ('application_id', self.RE_APP),
            ('sku_id', self.RE_SKU),
            ('kms_id', self.RE_KMS),
            ('client_machine_id', self.RE_CMID),
            ('previous_client_machine_id', self.RE_PREV),
            ('request_timestamp_utc', self.RE_REQTS),
            ('workstation_name', self.RE_WS),
            ('response_epid', self.RE_EPID),
        ]
        for field, pat in checks:
            m = pat.search(clean)
            if m:
                self.current[field] = m.group(1).strip()

        m = self.RE_LIC.search(clean)
        if m:
            self.current['license_status_code'] = int(m.group(1))
            self.current['license_status'] = m.group(2)

        for field, pat in [('n_count_policy', self.RE_NCOUNT),
                           ('active_clients', self.RE_ACTIVE),
                           ('renewal_interval', self.RE_RENEW),
                           ('activation_interval', self.RE_ACTINT)]:
            m = pat.search(clean)
            if m:
                self.current[field] = int(m.group(1))

        if self.RE_CONN_CLOSE.search(clean):
            if self.current and self.current.get('application_id'):
                self._save()

    def _save(self):
        if not self.current or not self.current.get('application_id'):
            self.current = None
            self.raw_lines = []
            return

        rec = self.current.copy()
        app_id = rec.get('application_id', '').lower()
        rec['application_name'] = APP_NAMES.get(app_id, 'Unknown')
        kms_id = rec.get('kms_id', '').lower()
        rec['kms_id_name'] = KMS_ID_NAMES.get(kms_id, 'Unknown')
        if not rec.get('license_status'):
            rec['license_status'] = LICENSE_STATUS.get(rec.get('license_status_code', 0), 'Unknown')
        rec['raw_log'] = '\n'.join(self.raw_lines)

        try:
            conn = get_db()
            conn.execute("""INSERT INTO activation_logs (
                timestamp, client_ip, client_port, protocol_version,
                is_virtual_machine, license_status, license_status_code,
                remaining_time_minutes, application_id, application_name,
                sku_id, kms_id, kms_id_name, client_machine_id,
                previous_client_machine_id, request_timestamp_utc,
                workstation_name, n_count_policy, response_epid,
                active_clients, renewal_interval, activation_interval, raw_log
            ) VALUES (
                :timestamp, :client_ip, :client_port, :protocol_version,
                :is_virtual_machine, :license_status, :license_status_code,
                :remaining_time_minutes, :application_id, :application_name,
                :sku_id, :kms_id, :kms_id_name, :client_machine_id,
                :previous_client_machine_id, :request_timestamp_utc,
                :workstation_name, :n_count_policy, :response_epid,
                :active_clients, :renewal_interval, :activation_interval, :raw_log
            )""", rec)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB error: {e}", flush=True)

        self.current = None
        self.raw_lines = []


def follow_log():
    parser = KMSLogParser()
    while not os.path.exists(LOG_PATH):
        time.sleep(2)
    with open(LOG_PATH, 'r') as f:
        for line in f:
            parser.parse_line(line)
        while True:
            line = f.readline()
            if line:
                parser.parse_line(line)
            else:
                time.sleep(0.5)


def start_kms_server():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    try:
        os.chown(os.path.dirname(LOG_PATH), 1000, 1000)
    except Exception:
        pass
    subprocess.Popen(['vlmcsd', '-v', '-l', LOG_PATH, '-t', '30', '-d'])
    print(f"vlmcsd started, logging to {LOG_PATH}", flush=True)


# ── Auth ──
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            return jsonify({'ok': False, 'msg': '未登录'}), 401
        if not api_rate_limit():
            return jsonify({'ok': False, 'msg': '请求过于频繁'}), 429
        return f(*args, **kwargs)
    return decorated


def check_auth(username, password):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM admin_users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return user and check_password_hash(user['password_hash'], password)


# ── Routes ──
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logs')
def logs_page():
    return render_template('logs.html')


@app.route('/settings')
def settings_page():
    return render_template('settings.html')


# ── 2FA pending sessions (in-memory, 3 min expiry) ──
_2fa_pending = {}  # {token: {"username": str, "expires": ts}}
_2fa_lock = threading.Lock()
_2FA_EXPIRY = 180  # 3 minutes


@app.route('/api/login', methods=['POST'])
def api_login():
    ip = get_client_ip()
    allowed, remaining, wait = check_rate_limit()
    if not allowed:
        return jsonify({
            'ok': False,
            'msg': f'IP已被封禁，请 {wait} 秒后重试',
            'locked': True,
            'wait': wait
        }), 429

    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if check_auth(username, password):
        # Check if 2FA is enabled for this user
        conn = get_db()
        user_row = conn.execute(
            "SELECT totp_secret FROM admin_users WHERE username=?", (username,)
        ).fetchone()
        conn.close()
        totp_secret = user_row['totp_secret'] if user_row else None

        if totp_secret:
            # Password OK but 2FA required — issue a pending token
            pending_token = secrets.token_hex(32)
            with _2fa_lock:
                # Clean expired
                now = time.time()
                for k in list(_2fa_pending):
                    if _2fa_pending[k]['expires'] < now:
                        del _2fa_pending[k]
                _2fa_pending[pending_token] = {
                    'username': username,
                    'expires': now + _2FA_EXPIRY
                }
            clear_attempts()
            return jsonify({
                'ok': False,
                'requires_2fa': True,
                'pending_token': pending_token,
                'msg': '请输入两步验证码'
            })
        else:
            # No 2FA — login directly
            clear_attempts()
            session.clear()  # Clear any old session data
            session.permanent = True
            session['user'] = username
            csrf = generate_csrf_token()
            return jsonify({'ok': True, 'csrf_token': csrf})

    record_failed_attempt()
    _, remaining2, _ = check_rate_limit()
    if remaining2 <= 0:
        return jsonify({
            'ok': False,
            'msg': f'失败次数过多，IP已封禁 {LOCKOUT_MINUTES} 分钟',
            'locked': True,
            'wait': LOCKOUT_MINUTES * 60
        }), 429

    return jsonify({
        'ok': False,
        'msg': f'用户名或密码错误，剩余尝试次数: {remaining2}',
        'remaining': remaining2
    }), 401


# ── 2FA attempt tracking (per pending_token) ──
_2FA_MAX_ATTEMPTS = 5


@app.route('/api/login/verify-2fa', methods=['POST'])
def api_verify_2fa():
    data = request.get_json() or {}
    pending_token = data.get('pending_token', '')
    code_str = data.get('code', '').strip()

    if not pending_token or not code_str:
        return jsonify({'ok': False, 'msg': '请填写验证码'}), 400

    # Validate pending token (peek, don't pop yet)
    with _2fa_lock:
        now = time.time()
        # Clean expired
        for k in list(_2fa_pending):
            if _2fa_pending[k]['expires'] < now:
                del _2fa_pending[k]
        pending = _2fa_pending.get(pending_token)

    if not pending:
        return jsonify({'ok': False, 'msg': '验证已超时，请重新登录'}), 403

    # Check attempt count
    attempts = pending.get('attempts', 0)
    if attempts >= _2FA_MAX_ATTEMPTS:
        with _2fa_lock:
            _2fa_pending.pop(pending_token, None)
        return jsonify({'ok': False, 'msg': f'验证码错误次数过多，请重新登录'}), 403

    username = pending['username']
    conn = get_db()
    user_row = conn.execute(
        "SELECT totp_secret FROM admin_users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    if not user_row or not user_row['totp_secret']:
        return jsonify({'ok': False, 'msg': '2FA未启用'}), 400

    totp = pyotp.TOTP(user_row['totp_secret'])
    if not totp.verify(code_str, valid_window=1):
        # Increment attempt count
        with _2fa_lock:
            pending['attempts'] = attempts + 1
            _2fa_pending[pending_token] = pending
        remaining = _2FA_MAX_ATTEMPTS - pending['attempts']
        return jsonify({'ok': False, 'msg': f'验证码错误，剩余尝试次数: {remaining}'}), 401

    # 2FA verified — pop token and complete login
    with _2fa_lock:
        _2fa_pending.pop(pending_token, None)

    session.clear()  # Clear any old session data
    session.permanent = True
    session['user'] = username
    csrf = generate_csrf_token()
    return jsonify({'ok': True, 'csrf_token': csrf})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/check')
def api_check():
    """Check if session is valid. Include health data to save a round trip."""
    logged_in = bool(session.get('user'))
    resp = {'logged_in': logged_in}
    if logged_in:
        resp['health'] = check_kms_health()
        resp['csrf_token'] = generate_csrf_token()
    return jsonify(resp)


def check_kms_health():
    """Check KMS service health: process, port, DB, log."""
    health = {
        'kms_process': False,
        'kms_port': False,
        'database': False,
        'log_file': False,
        'log_size': 0,
        'uptime': '-',
        'db_records': 0,
    }

    try:
        result = subprocess.run(['pgrep', '-x', 'vlmcsd'], capture_output=True, timeout=3)
        health['kms_process'] = result.returncode == 0
    except Exception:
        health['kms_process'] = False

    try:
        target_port = format(1688, '04X')
        with open('/proc/net/tcp') as tf:
            for line in tf:
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[1]
                    state = parts[3]
                    if local.endswith(f':{target_port}') and state == '0A':
                        health['kms_port'] = True
                        break
    except Exception:
        health['kms_port'] = False

    try:
        conn = get_db()
        health['database'] = True
        health['db_records'] = conn.execute(
            "SELECT COUNT(*) as c FROM activation_logs"
        ).fetchone()['c']
        conn.close()
    except Exception:
        health['database'] = False

    try:
        if os.path.exists(LOG_PATH):
            health['log_file'] = True
            health['log_size'] = os.path.getsize(LOG_PATH)
    except Exception:
        pass

    try:
        pid_result = subprocess.run(
            ['pgrep', '-x', 'vlmcsd'], capture_output=True, timeout=3, text=True
        )
        if pid_result.returncode == 0:
            pid = pid_result.stdout.strip().split('\n')[0]
            with open(f'/proc/{pid}/stat') as sf:
                stat_parts = sf.read().split()
                starttime_ticks = int(stat_parts[21])
            ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            with open('/proc/uptime') as uf:
                system_uptime = float(uf.read().split()[0])
            proc_start = starttime_ticks / ticks_per_sec
            proc_uptime = int(system_uptime - proc_start)
            days = proc_uptime // 86400
            hours = (proc_uptime % 86400) // 3600
            mins = (proc_uptime % 3600) // 60
            if days > 0:
                health['uptime'] = f"{days}天{hours}时{mins}分"
            elif hours > 0:
                health['uptime'] = f"{hours}时{mins}分"
            else:
                health['uptime'] = f"{mins}分"
    except Exception:
        pass

    health['status'] = 'running' if (
        health['kms_process'] and health['kms_port'] and health['database']
    ) else 'degraded'

    return health


@app.route('/api/health')
@login_required
def api_health():
    """Service health check."""
    return jsonify(check_kms_health())


@app.route('/api/stats')
@login_required
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM activation_logs").fetchone()['c']
    unique_ips = conn.execute(
        "SELECT COUNT(DISTINCT client_ip) as c FROM activation_logs WHERE client_ip IS NOT NULL"
    ).fetchone()['c']
    unique_machines = conn.execute(
        "SELECT COUNT(DISTINCT client_machine_id) as c FROM activation_logs WHERE client_machine_id IS NOT NULL"
    ).fetchone()['c']
    unique_workstations = conn.execute(
        "SELECT COUNT(DISTINCT workstation_name) as c FROM activation_logs WHERE workstation_name IS NOT NULL AND workstation_name != ''"
    ).fetchone()['c']
    today = datetime.now().strftime("%Y-%m-%d")
    today_count = conn.execute(
        "SELECT COUNT(*) as c FROM activation_logs WHERE timestamp LIKE ?", (f"{today}%",)
    ).fetchone()['c']

    by_app = conn.execute(
        "SELECT application_name, COUNT(*) as count FROM activation_logs GROUP BY application_name ORDER BY count DESC"
    ).fetchall()

    top_workstations = conn.execute("""
        SELECT workstation_name, client_ip, COUNT(*) as count, MAX(timestamp) as last_seen
        FROM activation_logs
        WHERE workstation_name IS NOT NULL AND workstation_name != ''
        GROUP BY workstation_name ORDER BY last_seen DESC LIMIT 10
    """).fetchall()

    recent_24h = conn.execute("""
        SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
        FROM activation_logs WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour ORDER BY hour
    """).fetchall()

    latest = conn.execute("SELECT * FROM activation_logs ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()

    return jsonify({
        'total': total,
        'unique_ips': unique_ips,
        'unique_machines': unique_machines,
        'unique_workstations': unique_workstations,
        'today': today_count,
        'by_app': [dict(r) for r in by_app],
        'top_workstations': [dict(r) for r in top_workstations],
        'recent_24h': [dict(r) for r in recent_24h],
        'latest': dict(latest) if latest else None,
    })


@app.route('/api/logs')
@login_required
def api_logs():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(max(1, int(request.args.get('per_page', 20))), 100)
    except (ValueError, TypeError):
        per_page = 20
    search = request.args.get('search', '').strip()
    app_filter = request.args.get('app', '').strip()

    where = "WHERE 1=1"
    params = []
    if search:
        where += " AND (workstation_name LIKE ? OR client_ip LIKE ? OR client_machine_id LIKE ?)"
        p = f"%{search}%"
        params += [p, p, p]
    if app_filter:
        where += " AND application_name=?"
        params.append(app_filter)

    conn = get_db()
    total = conn.execute(f"SELECT COUNT(*) as c FROM activation_logs {where}", params).fetchone()['c']
    logs = conn.execute(
        f"SELECT * FROM activation_logs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()
    conn.close()

    return jsonify({
        'logs': [dict(l) for l in logs],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page if total > 0 else 1,
    })


@app.route('/api/export')
@login_required
def api_export():
    conn = get_db()
    logs = conn.execute("SELECT * FROM activation_logs ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])


@app.route('/api/account', methods=['GET'])
@login_required
def api_account():
    """Get current account info."""
    return jsonify({'username': session.get('user', '')})


@app.route('/api/change-password', methods=['POST'])
@login_required
@csrf_protect
def api_change_password():
    """Change password. Requires current password verification."""
    data = request.get_json() or {}
    current_pass = data.get('current_password', '')
    new_pass = data.get('new_password', '')

    if not current_pass or not new_pass:
        return jsonify({'ok': False, 'msg': '请填写当前密码和新密码'}), 400

    if len(new_pass) < 6:
        return jsonify({'ok': False, 'msg': '新密码至少6位'}), 400

    username = session.get('user')
    if not check_auth(username, current_pass):
        return jsonify({'ok': False, 'msg': '当前密码错误'}), 403

    conn = get_db()
    conn.execute(
        """UPDATE admin_users SET password_hash=?
           WHERE username=?""",
        (generate_password_hash(new_pass), username)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'msg': '密码修改成功'})


@app.route('/api/change-username', methods=['POST'])
@login_required
@csrf_protect
def api_change_username():
    """Change username. Requires current password verification."""
    data = request.get_json() or {}
    current_pass = data.get('current_password', '')
    new_user = data.get('new_username', '').strip()

    if not current_pass or not new_user:
        return jsonify({'ok': False, 'msg': '请填写当前密码和新用户名'}), 400

    if len(new_user) < 3:
        return jsonify({'ok': False, 'msg': '用户名至少3个字符'}), 400

    username = session.get('user')
    if not check_auth(username, current_pass):
        return jsonify({'ok': False, 'msg': '当前密码错误'}), 403

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM admin_users WHERE username=? AND username!=?",
        (new_user, username)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({'ok': False, 'msg': '用户名已存在'}), 409

    conn.execute(
        "UPDATE admin_users SET username=? WHERE username=?",
        (new_user, username)
    )
    conn.commit()
    conn.close()

    session['user'] = new_user
    return jsonify({'ok': True, 'msg': '用户名修改成功', 'username': new_user})




# ── 2FA management ──
@app.route('/api/2fa/status')
@login_required
def api_2fa_status():
    """Check if 2FA is enabled for current user."""
    username = session.get('user')
    conn = get_db()
    row = conn.execute(
        "SELECT totp_secret FROM admin_users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return jsonify({'enabled': bool(row and row['totp_secret'])})


@app.route('/api/2fa/setup', methods=['POST'])
@login_required
@csrf_protect
def api_2fa_setup():
    """Generate a new TOTP secret and return otpauth URI."""
    username = session.get('user')
    # Generate new secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="ywsj-kms")
    # Store in session temporarily (not saved to DB until verified)
    session['_pending_totp_secret'] = secret
    return jsonify({'secret': secret, 'uri': uri})


@app.route('/api/2fa/confirm', methods=['POST'])
@login_required
@csrf_protect
def api_2fa_confirm():
    """Verify the TOTP code and save the secret to DB."""
    data = request.get_json() or {}
    code_str = data.get('code', '').strip()
    secret = session.get('_pending_totp_secret')

    if not secret or not code_str:
        return jsonify({'ok': False, 'msg': '请先获取二维码并输入验证码'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code_str, valid_window=1):
        return jsonify({'ok': False, 'msg': '验证码错误，请重试'}), 401

    # Save to DB
    username = session.get('user')
    conn = get_db()
    conn.execute(
        "UPDATE admin_users SET totp_secret=? WHERE username=?",
        (secret, username)
    )
    conn.commit()
    conn.close()

    # Clear pending secret
    session.pop('_pending_totp_secret', None)
    return jsonify({'ok': True, 'msg': '两步验证已启用'})


@app.route('/api/2fa/disable', methods=['POST'])
@login_required
@csrf_protect
def api_2fa_disable():
    """Disable 2FA. Requires current password verification."""
    data = request.get_json() or {}
    current_pass = data.get('current_password', '')

    if not current_pass:
        return jsonify({'ok': False, 'msg': '请输入当前密码'}), 400

    username = session.get('user')
    if not check_auth(username, current_pass):
        return jsonify({'ok': False, 'msg': '当前密码错误'}), 403

    conn = get_db()
    conn.execute(
        "UPDATE admin_users SET totp_secret=NULL WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'msg': '两步验证已关闭'})


# ── Background task startup (auto-starts on import for gunicorn) ──
_bg_started = False
_bg_lock = threading.Lock()


def _start_background_tasks():
    """init_db + log watcher thread. Idempotent — safe to call multiple times."""
    global _bg_started
    with _bg_lock:
        if _bg_started:
            return
        _bg_started = True
        try:
            init_db()
            t = threading.Thread(target=follow_log, daemon=True)
            t.start()
            print("Log watcher started", flush=True)
        except Exception as e:
            print(f"Failed to start background tasks: {e}", flush=True)


# Auto-start when imported by gunicorn
_start_background_tasks()


# ── Dev mode entrypoint ──
# Under gunicorn, __main__ is never executed — background tasks
# start via _start_background_tasks() above. In dev mode (python app.py),
# we also start vlmcsd here:
if __name__ == '__main__':
    start_kms_server()
    app.run(host='0.0.0.0', port=int(WEB_PORT), debug=False)
