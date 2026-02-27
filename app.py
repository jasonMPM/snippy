"""
to.ALWISP - URL Shortener & QR Code Generator
Flask Backend — Phase 3
New in Phase 3:
  - Users table with password hashing (pbkdf2)
  - JWT auth (access + refresh tokens)
  - Invite-only registration (admin generates invite links)
  - First registered user becomes admin
  - API key management
  - Team workspaces (personal + shared links)
  - Admin can view/manage all users and their links
"""

import os
import re
import sqlite3
import hashlib
import hmac
import secrets
import time
import io
import struct
import zlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, redirect, Response, make_response

try:
    import jwt as pyjwt
except ImportError:
    raise RuntimeError("PyJWT is required: pip install pyjwt")

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY environment variable must be set")

DB_PATH  = os.environ.get('DB_PATH',  '/app/data/sniplink.db')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000').rstrip('/')
JWT_ACCESS_EXPIRY  = int(os.environ.get('JWT_ACCESS_EXPIRY',  60 * 60 * 8))        # 8 hours
JWT_REFRESH_EXPIRY = int(os.environ.get('JWT_REFRESH_EXPIRY', 60 * 60 * 24 * 30))  # 30 days
# Secure cookies require HTTPS; set DEBUG=true to disable for local HTTP dev
COOKIE_SECURE = os.environ.get('DEBUG', 'false').lower() != 'true'


# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        # ── Step 1: Create all tables (IF NOT EXISTS — safe on fresh or existing db) ──
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                email        TEXT UNIQUE NOT NULL,
                display_name TEXT,
                pw_hash      TEXT NOT NULL,
                is_admin     INTEGER DEFAULT 0,
                is_active    INTEGER DEFAULT 1,
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                key_hash   TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                label      TEXT,
                last_used  TEXT,
                created_at TEXT NOT NULL,
                is_active  INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS invites (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      TEXT UNIQUE NOT NULL,
                created_by INTEGER NOT NULL,
                used_by    INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at    TEXT,
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (used_by)    REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS workspaces (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                slug       TEXT UNIQUE NOT NULL,
                owner_id   INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS workspace_members (
                workspace_id INTEGER NOT NULL,
                user_id      INTEGER NOT NULL,
                role         TEXT DEFAULT 'member',
                joined_at    TEXT NOT NULL,
                PRIMARY KEY (workspace_id, user_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
                FOREIGN KEY (user_id)      REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS links (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                code         TEXT UNIQUE NOT NULL,
                long_url     TEXT NOT NULL,
                title        TEXT,
                created_at   TEXT NOT NULL,
                expires_at   TEXT,
                clicks       INTEGER DEFAULT 0,
                is_active    INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS clicks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id    INTEGER NOT NULL,
                clicked_at TEXT NOT NULL,
                referrer   TEXT,
                user_agent TEXT,
                FOREIGN KEY (link_id) REFERENCES links(id)
            );
            CREATE TABLE IF NOT EXISTS tags (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS link_tags (
                link_id INTEGER NOT NULL,
                tag_id  INTEGER NOT NULL,
                PRIMARY KEY (link_id, tag_id),
                FOREIGN KEY (link_id) REFERENCES links(id),
                FOREIGN KEY (tag_id)  REFERENCES tags(id)
            );
            CREATE INDEX IF NOT EXISTS idx_links_code  ON links(code);
            CREATE INDEX IF NOT EXISTS idx_clicks_link ON clicks(link_id);
            CREATE INDEX IF NOT EXISTS idx_clicks_at   ON clicks(clicked_at);
            CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);
        """)

        # ── Step 2: Migrations — add new columns to existing tables if missing ──
        # SQLite has no ADD COLUMN IF NOT EXISTS, so we try each and ignore if already there.
        migrations = [
            "ALTER TABLE links ADD COLUMN owner_id     INTEGER REFERENCES users(id)",
            "ALTER TABLE links ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id)",
        ]
        for sql in migrations:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass  # Column already exists — safe to ignore

        # ── Step 3: Indexes on the (possibly just-added) columns ──
        conn.executescript("""
            CREATE INDEX IF NOT EXISTS idx_links_owner ON links(owner_id);
            CREATE INDEX IF NOT EXISTS idx_links_ws    ON links(workspace_id);
        """)

init_db()


# ─────────────────────────────────────────────
# Password helpers
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
    return f"pbkdf2$sha256$260000${salt}${h.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        _, algo, iters, salt, stored_hash = stored.split('$')
        h = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(h.hex(), stored_hash)
    except Exception:
        return False


# ─────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────

def make_access_token(user_id: int, is_admin: bool) -> str:
    payload = {
        'sub':      user_id,
        'admin':    is_admin,
        'type':     'access',
        'exp':      datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=JWT_ACCESS_EXPIRY),
        'iat':      datetime.now(timezone.utc).replace(tzinfo=None),
    }
    return pyjwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def make_refresh_token_pair(user_id: int) -> tuple:
    """Returns (raw_token, token_hash, expires_at_iso)"""
    raw     = secrets.token_urlsafe(48)
    h       = hashlib.sha256(raw.encode()).hexdigest()
    expires = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=JWT_REFRESH_EXPIRY)
    return raw, h, expires.isoformat()

def decode_access_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None


# ─────────────────────────────────────────────
# Cookie helpers
# ─────────────────────────────────────────────

def set_auth_cookies(resp, access_tok: str, refresh_tok: str):
    """Attach HttpOnly auth cookies to a response.
    Cookies bypass Nginx Proxy Manager header-stripping and are sent
    automatically by the browser on every same-origin request.
    """
    resp.set_cookie('access_token',  access_tok,
                    httponly=True, secure=COOKIE_SECURE, samesite='Lax',
                    max_age=JWT_ACCESS_EXPIRY,  path='/')
    resp.set_cookie('refresh_token', refresh_tok,
                    httponly=True, secure=COOKIE_SECURE, samesite='Lax',
                    max_age=JWT_REFRESH_EXPIRY, path='/')
    return resp

def clear_auth_cookies(resp):
    resp.set_cookie('access_token',  '', expires=0, path='/')
    resp.set_cookie('refresh_token', '', expires=0, path='/')
    return resp


# ─────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────

def get_token_from_request():
    """Extract Bearer token or API key from request.
    Priority: cookie (browser clients, survives NPM proxy) →
              X-Auth-Token header (legacy / API clients) →
              Authorization: Bearer → X-API-Key.
    """
    # Primary: HttpOnly cookie — the browser sends it automatically and
    # Nginx Proxy Manager does NOT strip cookies (unlike custom headers).
    cookie_token = request.cookies.get('access_token', '').strip()
    if cookie_token:
        return ('bearer', cookie_token)
    # Fallback: custom header kept for direct API / non-browser clients
    token = request.headers.get('X-Auth-Token', '').strip()
    if token:
        return ('bearer', token)
    # Standard Authorization header
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return ('bearer', auth[7:])
    api_key = request.headers.get('X-API-Key', '')
    if api_key:
        return ('apikey', api_key)
    return (None, None)

def resolve_user():
    """Return user row or None."""
    kind, token = get_token_from_request()
    if not token:
        return None
    if kind == 'bearer':
        payload = decode_access_token(token)
        if not payload or payload.get('type') != 'access':
            return None
        with get_db() as conn:
            return conn.execute(
                'SELECT * FROM users WHERE id = ? AND is_active = 1', (payload['sub'],)
            ).fetchone()
    if kind == 'apikey':
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        with get_db() as conn:
            key_row = conn.execute(
                'SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1', (key_hash,)
            ).fetchone()
            if not key_row:
                return None
            conn.execute('UPDATE api_keys SET last_used = ? WHERE id = ?',
                         (datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), key_row['id']))
            return conn.execute(
                'SELECT * FROM users WHERE id = ? AND is_active = 1', (key_row['user_id'],)
            ).fetchone()
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = resolve_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        return f(user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = resolve_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        if not user['is_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(user, *args, **kwargs)
    return decorated

def optional_auth(f):
    """Passes user (or None) as first argument."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = resolve_user()
        return f(user, *args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# QR Generator
# ─────────────────────────────────────────────

def generate_qr_png(data: str, size: int = 300, fg=(0,0,0), bg=(255,255,255)) -> bytes:
    try:
        import qrcode as qrc
        qr = qrc.QRCode(border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color=fg, back_color=bg)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except ImportError:
        pass
    module_count = 21
    cell = max(4, size // module_count)
    img_size = cell * module_count
    pixels = []
    for row in range(img_size):
        row_pixels = b''
        for col in range(img_size):
            r, c = row // cell, col // cell
            in_finder = (
                (r < 7 and c < 7) or (r < 7 and c >= module_count - 7) or
                (r >= module_count - 7 and c < 7)
            )
            is_dark = False
            if in_finder:
                lr, lc = r % 7, c % 7
                is_dark = (lr == 0 or lr == 6 or lc == 0 or lc == 6 or
                           (2 <= lr <= 4 and 2 <= lc <= 4))
            elif (row // cell + col // cell) % 2 == 0:
                is_dark = (r == 6 or c == 6) and (r % 2 == 0 or c % 2 == 0)
            row_pixels += bytes(fg if is_dark else bg)
        pixels.append(row_pixels)

    def png_chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    raw = b''.join(b'\x00' + row for row in pixels)
    return (b'\x89PNG\r\n\x1a\n'
            + png_chunk(b'IHDR', struct.pack('>IIBBBBB', img_size, img_size, 8, 2, 0, 0, 0))
            + png_chunk(b'IDAT', zlib.compress(raw))
            + png_chunk(b'IEND', b''))


# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────

def generate_code(url: str, length: int = 6) -> str:
    return hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:length]

def validate_url(url: str) -> bool:
    return url.startswith(('http://', 'https://'))

def hex_to_rgb(h):
    h = h.lstrip('#')
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def parse_device(ua):
    if not ua: return 'Unknown'
    u = ua.lower()
    if any(x in u for x in ('mobile','android','iphone')): return 'Mobile'
    if any(x in u for x in ('tablet','ipad')):             return 'Tablet'
    return 'Desktop'

def parse_browser(ua):
    if not ua: return 'Unknown'
    u = ua.lower()
    if 'edg/' in u:     return 'Edge'
    if 'opr/' in u:     return 'Opera'
    if 'chrome/' in u:  return 'Chrome'
    if 'firefox/' in u: return 'Firefox'
    if 'safari/' in u:  return 'Safari'
    if 'curl' in u:     return 'curl'
    if 'python' in u:   return 'Python'
    return 'Other'

def parse_referrer(ref):
    if not ref: return 'Direct'
    r = ref.lower()
    if 'google' in r:                          return 'Google'
    if 'bing' in r:                            return 'Bing'
    if 'facebook' in r or 'fb.com' in r:       return 'Facebook'
    if 'twitter' in r or 't.co' in r or 'x.com' in r: return 'Twitter/X'
    if 'linkedin' in r:                        return 'LinkedIn'
    if 'reddit' in r:                          return 'Reddit'
    if 'youtube' in r:                         return 'YouTube'
    if 'instagram' in r:                       return 'Instagram'
    return 'Other'

def get_link_tags(conn, link_id):
    rows = conn.execute(
        'SELECT t.id, t.name FROM tags t JOIN link_tags lt ON t.id=lt.tag_id WHERE lt.link_id=?',
        (link_id,)
    ).fetchall()
    return [{'id': r['id'], 'name': r['name']} for r in rows]

def set_link_tags(conn, link_id, tag_names):
    conn.execute('DELETE FROM link_tags WHERE link_id=?', (link_id,))
    for name in tag_names:
        name = name.strip().lower()
        if not name: continue
        conn.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (name,))
        tid = conn.execute('SELECT id FROM tags WHERE name=?', (name,)).fetchone()['id']
        conn.execute('INSERT OR IGNORE INTO link_tags (link_id,tag_id) VALUES (?,?)', (link_id, tid))

def format_link(row, conn):
    return {
        'id':           row['id'],
        'code':         row['code'],
        'long_url':     row['long_url'],
        'title':        row['title'],
        'created_at':   row['created_at'],
        'expires_at':   row['expires_at'],
        'clicks':       row['clicks'],
        'is_active':    row['is_active'],
        'owner_id':     row['owner_id'],
        'workspace_id': row['workspace_id'],
        'short_url':    f"{BASE_URL}/{row['code']}",
        'qr_url':       f"{BASE_URL}/api/qr/{row['code']}",
        'tags':         get_link_tags(conn, row['id']),
    }

def format_user(row):
    return {
        'id':           row['id'],
        'email':        row['email'],
        'display_name': row['display_name'],
        'is_admin':     bool(row['is_admin']),
        'is_active':    bool(row['is_active']),
        'created_at':   row['created_at'],
    }


# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data         = request.get_json(silent=True) or {}
    email        = (data.get('email') or '').strip().lower()
    password     = data.get('password') or ''
    display_name = (data.get('display_name') or '').strip()
    invite_token = (data.get('invite_token') or '').strip()

    if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    with get_db() as conn:
        # Check if any users exist — first user skips invite requirement
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        is_first   = user_count == 0

        if not is_first:
            if not invite_token:
                return jsonify({'error': 'Invite token required'}), 403
            invite = conn.execute(
                'SELECT * FROM invites WHERE token=? AND used_by IS NULL AND expires_at > ?',
                (invite_token, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
            ).fetchone()
            if not invite:
                return jsonify({'error': 'Invalid or expired invite token'}), 403

        if conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
            return jsonify({'error': 'Email already registered'}), 409

        pw_hash = hash_password(password)
        conn.execute(
            'INSERT INTO users (email, display_name, pw_hash, is_admin, created_at) VALUES (?,?,?,?,?)',
            (email, display_name or email.split('@')[0], pw_hash,
             1 if is_first else 0, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
        user_id = conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()['id']

        if not is_first:
            conn.execute(
                'UPDATE invites SET used_by=?, used_at=? WHERE token=?',
                (user_id, datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), invite_token)
            )

        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    access  = make_access_token(user['id'], bool(user['is_admin']))
    raw, h, exp = make_refresh_token_pair(user['id'])
    with get_db() as conn:
        conn.execute(
            'INSERT INTO refresh_tokens (user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)',
            (user['id'], h, exp, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )

    resp = make_response(jsonify({
        'access_token':  access,
        'refresh_token': raw,
        'user':          format_user(user),
    }), 201)
    set_auth_cookies(resp, access, raw)
    return resp


@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    with get_db() as conn:
        user = conn.execute(
            'SELECT * FROM users WHERE email=? AND is_active=1', (email,)
        ).fetchone()

    if not user or not verify_password(password, user['pw_hash']):
        return jsonify({'error': 'Invalid email or password'}), 401

    access = make_access_token(user['id'], bool(user['is_admin']))
    raw, h, exp = make_refresh_token_pair(user['id'])
    with get_db() as conn:
        conn.execute(
            'INSERT INTO refresh_tokens (user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)',
            (user['id'], h, exp, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )

    resp = make_response(jsonify({
        'access_token':  access,
        'refresh_token': raw,
        'user':          format_user(user),
    }))
    set_auth_cookies(resp, access, raw)
    return resp


@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.get_json(silent=True) or {}
    # Accept refresh token from JSON body (frontend) OR HttpOnly cookie (fallback)
    raw  = (data.get('refresh_token') or request.cookies.get('refresh_token') or '').strip()
    if not raw:
        return jsonify({'error': 'Refresh token required'}), 400

    h = hashlib.sha256(raw.encode()).hexdigest()
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM refresh_tokens WHERE token_hash=? AND expires_at > ?',
            (h, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        ).fetchone()
        if not row:
            return jsonify({'error': 'Invalid or expired refresh token'}), 401

        user = conn.execute(
            'SELECT * FROM users WHERE id=? AND is_active=1', (row['user_id'],)
        ).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        # Only rotate the refresh token when it's within 24 hours of expiry.
        # This prevents concurrent requests (e.g. dashboard loading multiple
        # endpoints at once) from each triggering a rotation that invalidates
        # the others, which would cause a spurious logout.
        expires_at  = datetime.fromisoformat(row['expires_at'])
        rotate      = expires_at - datetime.now(timezone.utc).replace(tzinfo=None) < timedelta(hours=24)

        if rotate:
            conn.execute('DELETE FROM refresh_tokens WHERE token_hash=?', (h,))
            new_raw, new_h, new_exp = make_refresh_token_pair(user['id'])
            conn.execute(
                'INSERT INTO refresh_tokens (user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)',
                (user['id'], new_h, new_exp, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
            )
        else:
            new_raw = raw  # Return the same refresh token — it's still valid

    new_access = make_access_token(user['id'], bool(user['is_admin']))
    resp = make_response(jsonify({
        'access_token':  new_access,
        'refresh_token': new_raw,
    }))
    set_auth_cookies(resp, new_access, new_raw)
    return resp


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout(current_user):
    data = request.get_json(silent=True) or {}
    # Accept refresh token from body OR cookie
    raw  = data.get('refresh_token', '') or request.cookies.get('refresh_token', '')
    if raw:
        h = hashlib.sha256(raw.encode()).hexdigest()
        with get_db() as conn:
            conn.execute('DELETE FROM refresh_tokens WHERE token_hash=?', (h,))
    resp = make_response(jsonify({'success': True}))
    clear_auth_cookies(resp)
    return resp


@app.route('/api/auth/me', methods=['GET'])
@login_required
def me(current_user):
    return jsonify(format_user(current_user))


# ─────────────────────────────────────────────
# API Keys
# ─────────────────────────────────────────────

@app.route('/api/auth/keys', methods=['GET'])
@login_required
def list_keys(current_user):
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id, key_prefix, label, last_used, created_at, is_active '
            'FROM api_keys WHERE user_id=? ORDER BY created_at DESC',
            (current_user['id'],)
        ).fetchall()
    return jsonify({'keys': [dict(r) for r in rows]})


@app.route('/api/auth/keys', methods=['POST'])
@login_required
def create_key(current_user):
    data  = request.get_json(silent=True) or {}
    label = (data.get('label') or '').strip() or 'API Key'
    raw   = 'snip_' + secrets.token_urlsafe(32)
    h     = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:12] + '...'
    with get_db() as conn:
        conn.execute(
            'INSERT INTO api_keys (user_id,key_hash,key_prefix,label,created_at) VALUES (?,?,?,?,?)',
            (current_user['id'], h, prefix, label, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
        key_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    return jsonify({'id': key_id, 'key': raw, 'prefix': prefix, 'label': label}), 201


@app.route('/api/auth/keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_key(current_user, key_id):
    with get_db() as conn:
        conn.execute(
            'UPDATE api_keys SET is_active=0 WHERE id=? AND user_id=?',
            (key_id, current_user['id'])
        )
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Invites (admin only)
# ─────────────────────────────────────────────

@app.route('/api/admin/invites', methods=['POST'])
@admin_required
def create_invite(current_user):
    token      = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=7)).isoformat()
    with get_db() as conn:
        conn.execute(
            'INSERT INTO invites (token,created_by,created_at,expires_at) VALUES (?,?,?,?)',
            (token, current_user['id'], datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), expires_at)
        )
    invite_url = f"{BASE_URL}/register?invite={token}"
    return jsonify({'token': token, 'invite_url': invite_url, 'expires_at': expires_at}), 201


@app.route('/api/admin/invites', methods=['GET'])
@admin_required
def list_invites(current_user):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT i.*, u.email as used_by_email
            FROM invites i LEFT JOIN users u ON i.used_by=u.id
            ORDER BY i.created_at DESC
        """).fetchall()
    return jsonify({'invites': [dict(r) for r in rows]})


# ─────────────────────────────────────────────
# Admin — Users
# ─────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users(current_user):
    with get_db() as conn:
        rows = conn.execute(
            'SELECT u.*, COUNT(l.id) as link_count '
            'FROM users u LEFT JOIN links l ON u.id=l.owner_id AND l.is_active=1 '
            'GROUP BY u.id ORDER BY u.created_at DESC'
        ).fetchall()
    return jsonify({'users': [dict(r) for r in rows]})


@app.route('/api/admin/users/<int:user_id>', methods=['PATCH'])
@admin_required
def admin_edit_user(current_user, user_id):
    data = request.get_json(silent=True) or {}
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        updates = {}
        if 'is_active' in data: updates['is_active'] = int(bool(data['is_active']))
        if 'is_admin'  in data: updates['is_admin']  = int(bool(data['is_admin']))
        if updates:
            set_clause = ', '.join(f'{k}=?' for k in updates)
            conn.execute(f'UPDATE users SET {set_clause} WHERE id=?',
                         list(updates.values()) + [user_id])
        updated = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    return jsonify(format_user(updated))


@app.route('/api/admin/users/<int:user_id>/links', methods=['GET'])
@admin_required
def admin_user_links(current_user, user_id):
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM links WHERE owner_id=? AND is_active=1 ORDER BY created_at DESC',
            (user_id,)
        ).fetchall()
        links = [format_link(r, conn) for r in rows]
    return jsonify({'links': links})


# ─────────────────────────────────────────────
# Workspaces
# ─────────────────────────────────────────────

def slugify(name: str) -> str:
    s = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    return s[:40] or 'workspace'

@app.route('/api/workspaces', methods=['GET'])
@login_required
def list_workspaces(current_user):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT w.*, wm.role,
                   (SELECT COUNT(*) FROM links l WHERE l.workspace_id=w.id AND l.is_active=1) as link_count,
                   (SELECT COUNT(*) FROM workspace_members wm2 WHERE wm2.workspace_id=w.id) as member_count
            FROM workspaces w
            JOIN workspace_members wm ON w.id=wm.workspace_id
            WHERE wm.user_id=?
            ORDER BY w.created_at DESC
        """, (current_user['id'],)).fetchall()
    return jsonify({'workspaces': [dict(r) for r in rows]})


@app.route('/api/workspaces', methods=['POST'])
@login_required
def create_workspace(current_user):
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Workspace name required'}), 400

    slug = slugify(name)
    with get_db() as conn:
        # Ensure unique slug
        base_slug, n = slug, 1
        while conn.execute('SELECT id FROM workspaces WHERE slug=?', (slug,)).fetchone():
            slug = f"{base_slug}-{n}"; n += 1

        conn.execute(
            'INSERT INTO workspaces (name,slug,owner_id,created_at) VALUES (?,?,?,?)',
            (name, slug, current_user['id'], datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
        ws_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute(
            'INSERT INTO workspace_members (workspace_id,user_id,role,joined_at) VALUES (?,?,?,?)',
            (ws_id, current_user['id'], 'owner', datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
        ws = conn.execute('SELECT * FROM workspaces WHERE id=?', (ws_id,)).fetchone()
    return jsonify(dict(ws)), 201


@app.route('/api/workspaces/<int:ws_id>/members', methods=['GET'])
@login_required
def workspace_members(current_user, ws_id):
    with get_db() as conn:
        member = conn.execute(
            'SELECT * FROM workspace_members WHERE workspace_id=? AND user_id=?',
            (ws_id, current_user['id'])
        ).fetchone()
        if not member and not current_user['is_admin']:
            return jsonify({'error': 'Not a member'}), 403
        rows = conn.execute("""
            SELECT u.id, u.email, u.display_name, wm.role, wm.joined_at
            FROM workspace_members wm JOIN users u ON wm.user_id=u.id
            WHERE wm.workspace_id=?
        """, (ws_id,)).fetchall()
    return jsonify({'members': [dict(r) for r in rows]})


@app.route('/api/workspaces/<int:ws_id>/members', methods=['POST'])
@login_required
def add_workspace_member(current_user, ws_id):
    with get_db() as conn:
        ws = conn.execute('SELECT * FROM workspaces WHERE id=?', (ws_id,)).fetchone()
        if not ws:
            return jsonify({'error': 'Workspace not found'}), 404
        my_role = conn.execute(
            'SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=?',
            (ws_id, current_user['id'])
        ).fetchone()
        if not my_role or my_role['role'] not in ('owner', 'admin'):
            return jsonify({'error': 'Only workspace owners can add members'}), 403

        data  = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        role  = data.get('role', 'member')
        target = conn.execute('SELECT * FROM users WHERE email=? AND is_active=1', (email,)).fetchone()
        if not target:
            return jsonify({'error': 'User not found'}), 404
        existing = conn.execute(
            'SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=?',
            (ws_id, target['id'])
        ).fetchone()
        if existing:
            return jsonify({'error': 'Already a member'}), 409
        conn.execute(
            'INSERT INTO workspace_members (workspace_id,user_id,role,joined_at) VALUES (?,?,?,?)',
            (ws_id, target['id'], role, datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
    return jsonify({'success': True}), 201


# ─────────────────────────────────────────────
# Links (auth-aware)
# ─────────────────────────────────────────────

@app.route('/api/shorten', methods=['POST'])
@optional_auth
def shorten(current_user):
    data         = request.get_json(silent=True) or {}
    long_url     = (data.get('url') or '').strip()
    custom_code  = (data.get('custom_code') or '').strip()
    title        = (data.get('title') or '').strip()
    expires_at   = data.get('expires_at')
    tags         = data.get('tags', [])
    workspace_id = data.get('workspace_id')

    if not long_url:
        return jsonify({'error': 'URL is required'}), 400
    if not validate_url(long_url):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    if custom_code and not re.match(r'^[a-zA-Z0-9]{3,20}$', custom_code):
        return jsonify({'error': 'Custom code must be 3–20 alphanumeric characters'}), 400

    owner_id = current_user['id'] if current_user else None

    # Validate workspace membership
    if workspace_id and current_user:
        with get_db() as conn:
            member = conn.execute(
                'SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=?',
                (workspace_id, current_user['id'])
            ).fetchone()
            if not member:
                return jsonify({'error': 'Not a member of that workspace'}), 403

    code = custom_code or generate_code(long_url)

    with get_db() as conn:
        existing = conn.execute('SELECT code FROM links WHERE code=?', (code,)).fetchone()
        if existing:
            if custom_code:
                return jsonify({'error': 'Custom code already taken'}), 409
            code = generate_code(long_url + str(time.time()))

        conn.execute(
            'INSERT INTO links (code,long_url,title,created_at,expires_at,owner_id,workspace_id) '
            'VALUES (?,?,?,?,?,?,?)',
            (code, long_url, title or None, datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
             expires_at or None, owner_id, workspace_id)
        )
        link_id = conn.execute('SELECT id FROM links WHERE code=?', (code,)).fetchone()['id']
        if tags:
            set_link_tags(conn, link_id, tags)

    return jsonify({
        'code':      code,
        'short_url': f"{BASE_URL}/{code}",
        'long_url':  long_url,
        'title':     title,
        'tags':      tags,
        'qr_url':    f"{BASE_URL}/api/qr/{code}",
        'owner_id':  owner_id,
    }), 201


@app.route('/api/links', methods=['GET'])
@optional_auth
def list_links(current_user):
    page         = int(request.args.get('page', 1))
    per_page     = min(int(request.args.get('per_page', 20)), 100)
    offset       = (page - 1) * per_page
    search       = (request.args.get('q') or '').strip()
    tag_filter   = (request.args.get('tag') or '').strip().lower()
    workspace_id = request.args.get('workspace_id')
    all_links    = request.args.get('all') == '1'

    where_clauses = ['l.is_active=1']
    params = []

    if current_user:
        if current_user['is_admin'] and all_links:
            pass  # Admin sees everything
        elif workspace_id:
            where_clauses.append('l.workspace_id=?')
            params.append(workspace_id)
        else:
            where_clauses.append('(l.owner_id=? OR l.workspace_id IN ('
                                 'SELECT workspace_id FROM workspace_members WHERE user_id=?))')
            params += [current_user['id'], current_user['id']]
    else:
        # Unauthenticated — only show links with no owner (legacy/public)
        where_clauses.append('l.owner_id IS NULL')

    if search:
        where_clauses.append('(l.code LIKE ? OR l.long_url LIKE ? OR l.title LIKE ?)')
        s = f'%{search}%'
        params += [s, s, s]
    if tag_filter:
        where_clauses.append(
            'l.id IN (SELECT lt.link_id FROM link_tags lt '
            'JOIN tags t ON lt.tag_id=t.id WHERE t.name=?)'
        )
        params.append(tag_filter)

    where_sql = ' AND '.join(where_clauses)
    with get_db() as conn:
        total = conn.execute(f'SELECT COUNT(*) FROM links l WHERE {where_sql}', params).fetchone()[0]
        rows  = conn.execute(
            f'SELECT * FROM links l WHERE {where_sql} ORDER BY l.created_at DESC LIMIT ? OFFSET ?',
            params + [per_page, offset]
        ).fetchall()
        links = [format_link(r, conn) for r in rows]

    return jsonify({'links': links, 'total': total, 'page': page, 'per_page': per_page})


@app.route('/api/links/<code>', methods=['GET'])
@optional_auth
def link_detail(current_user, code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(format_link(link, conn))


@app.route('/api/links/<code>', methods=['PATCH'])
@login_required
def edit_link(current_user, code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
        if not link:
            return jsonify({'error': 'Not found'}), 404
        if link['owner_id'] != current_user['id'] and not current_user['is_admin']:
            return jsonify({'error': 'Not authorised'}), 403

        data = request.get_json(silent=True) or {}
        updates = {}
        if 'url'        in data:
            url = data['url'].strip()
            if not validate_url(url): return jsonify({'error': 'Invalid URL'}), 400
            updates['long_url'] = url
        if 'title'      in data: updates['title']      = data['title'].strip() or None
        if 'expires_at' in data: updates['expires_at'] = data['expires_at'] or None

        if updates:
            set_clause = ', '.join(f'{k}=?' for k in updates)
            conn.execute(f'UPDATE links SET {set_clause} WHERE code=?',
                         list(updates.values()) + [code])
        if 'tags' in data:
            set_link_tags(conn, link['id'], data['tags'])

        updated = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        return jsonify(format_link(updated, conn))


@app.route('/api/links/<code>', methods=['DELETE'])
@login_required
def delete_link(current_user, code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link:
            return jsonify({'error': 'Not found'}), 404
        if link['owner_id'] != current_user['id'] and not current_user['is_admin']:
            return jsonify({'error': 'Not authorised'}), 403
        conn.execute('UPDATE links SET is_active=0 WHERE code=?', (code,))
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Analytics (auth-aware)
# ─────────────────────────────────────────────

@app.route('/api/links/<code>/analytics')
@optional_auth
def link_analytics(current_user, code):
    days = int(request.args.get('days', 30))
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link:
            return jsonify({'error': 'Not found'}), 404

        link_id = link['id']
        since   = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)).isoformat()

        daily_rows = conn.execute("""
            SELECT substr(clicked_at,1,10) as day, COUNT(*) as count
            FROM clicks WHERE link_id=? AND clicked_at>=?
            GROUP BY day ORDER BY day
        """, (link_id, since)).fetchall()
        daily_map = {r['day']: r['count'] for r in daily_rows}
        daily = [
            {'date': (datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(days=days-1-i)).strftime('%Y-%m-%d'), 'clicks': 0}
            for i in range(days)
        ]
        for d in daily: d['clicks'] = daily_map.get(d['date'], 0)

        ref_rows = conn.execute(
            'SELECT referrer, COUNT(*) as count FROM clicks WHERE link_id=? AND clicked_at>=? GROUP BY referrer',
            (link_id, since)
        ).fetchall()
        referrers = {}
        for r in ref_rows:
            b = parse_referrer(r['referrer']); referrers[b] = referrers.get(b,0) + r['count']
        referrers = [{'source':k,'count':v} for k,v in sorted(referrers.items(), key=lambda x:-x[1])]

        ua_rows = conn.execute(
            'SELECT user_agent, COUNT(*) as count FROM clicks WHERE link_id=? AND clicked_at>=? GROUP BY user_agent',
            (link_id, since)
        ).fetchall()
        devices = {}; browsers = {}
        for r in ua_rows:
            ua = r['user_agent'] or ''
            devices[parse_device(ua)]   = devices.get(parse_device(ua),0)   + r['count']
            browsers[parse_browser(ua)] = browsers.get(parse_browser(ua),0) + r['count']
        devices  = [{'device':k,'count':v}  for k,v in sorted(devices.items(),  key=lambda x:-x[1])]
        browsers = [{'browser':k,'count':v} for k,v in sorted(browsers.items(), key=lambda x:-x[1])]

    return jsonify({
        'code': code, 'days': days,
        'total_clicks': link['clicks'],
        'period_clicks': sum(d['clicks'] for d in daily),
        'daily': daily, 'referrers': referrers, 'devices': devices, 'browsers': browsers,
    })


# ─────────────────────────────────────────────
# Tags & Stats
# ─────────────────────────────────────────────

@app.route('/api/tags')
@optional_auth
def list_tags(current_user):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT t.id, t.name, COUNT(lt.link_id) as link_count
            FROM tags t LEFT JOIN link_tags lt ON t.id=lt.tag_id
            GROUP BY t.id ORDER BY t.name
        """).fetchall()
    return jsonify({'tags': [dict(r) for r in rows]})


@app.route('/api/stats')
@optional_auth
def stats(current_user):
    owner_filter = ''
    params = []
    if current_user and not current_user['is_admin']:
        owner_filter = ' AND (l.owner_id=? OR l.workspace_id IN (SELECT workspace_id FROM workspace_members WHERE user_id=?))'
        params = [current_user['id'], current_user['id']]

    with get_db() as conn:
        total_links  = conn.execute(f'SELECT COUNT(*) FROM links l WHERE l.is_active=1{owner_filter}', params).fetchone()[0]
        total_clicks = conn.execute(f'SELECT COALESCE(SUM(l.clicks),0) FROM links l WHERE l.is_active=1{owner_filter}', params).fetchone()[0]
        since_7d     = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)).isoformat()
        clicks_7d    = conn.execute(
            f'SELECT COUNT(*) FROM clicks c JOIN links l ON c.link_id=l.id WHERE c.clicked_at>=? AND l.is_active=1{owner_filter}',
            [since_7d] + params
        ).fetchone()[0]
        top_links = conn.execute(
            f'SELECT l.code, l.long_url, l.title, l.clicks FROM links l WHERE l.is_active=1{owner_filter} ORDER BY l.clicks DESC LIMIT 5',
            params
        ).fetchall()

    return jsonify({
        'total_links':  total_links,
        'total_clicks': total_clicks,
        'clicks_7d':    clicks_7d,
        'top_links':    [dict(r) for r in top_links],
    })


# ─────────────────────────────────────────────
# QR Routes
# ─────────────────────────────────────────────

@app.route('/api/qr/<code>')
def qr_code(code):
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size   = min(int(request.args.get('size', 300)), 1000)
    with get_db() as conn:
        link = conn.execute('SELECT 1 FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404
    png = generate_qr_png(f"{BASE_URL}/{code}", size=size,
                          fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex))
    return Response(png, mimetype='image/png', headers={'Cache-Control': 'public, max-age=3600'})


@app.route('/api/qr/custom')
def qr_custom():
    url = request.args.get('url', '').strip()
    if not url or not validate_url(url):
        return jsonify({'error': 'Valid URL required'}), 400
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size   = min(int(request.args.get('size', 300)), 1000)
    png = generate_qr_png(url, size=size, fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex))
    return Response(png, mimetype='image/png')


# ─────────────────────────────────────────────
# Redirect
# ─────────────────────────────────────────────

@app.route('/<code>')
def redirect_link(code):
    if code in ('static', 'api', 'favicon.ico', 'register'):
        return 'Not found', 404
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
        if not link:
            return redirect('/?error=not_found')
        if link['expires_at'] and link['expires_at'] < datetime.now(timezone.utc).replace(tzinfo=None).isoformat():
            return redirect('/?error=expired')
        conn.execute(
            'INSERT INTO clicks (link_id,clicked_at,referrer,user_agent) VALUES (?,?,?,?)',
            (link['id'], datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
             request.referrer, request.headers.get('User-Agent','')[:500])
        )
        conn.execute('UPDATE links SET clicks=clicks+1 WHERE id=?', (link['id'],))
        return redirect(link['long_url'], code=301)


# ─────────────────────────────────────────────
# Frontend — catch-all
# ─────────────────────────────────────────────

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def frontend(path):
    # Only serve index for non-API, non-code paths
    if path.startswith('api/') or path.startswith('static/'):
        return 'Not found', 404
    with open(os.path.join(os.path.dirname(__file__), 'index.html')) as f:
        return f.read()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port,
            debug=os.environ.get('DEBUG', 'false').lower() == 'true')
