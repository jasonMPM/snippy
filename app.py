"""
Self-hosted URL shortener & QR code generator.
Single-admin auth: set ADMIN_PASSWORD env var. No accounts, no JWTs.
"""

import os
import re
import csv
import base64
import sqlite3
import hashlib
import hmac
import time
import io
import struct
import zlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, redirect, Response, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY environment variable must be set")

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable must be set")

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')

DB_PATH  = os.environ.get('DB_PATH',  '/app/data/qrknit.db')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000').rstrip('/')
APP_NAME = os.environ.get('APP_NAME', 'to.ALWISP')

COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = COOKIE_SECURE
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)


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
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin      INTEGER DEFAULT 0,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS links (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                code       TEXT UNIQUE NOT NULL,
                long_url   TEXT NOT NULL,
                title      TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                clicks     INTEGER DEFAULT 0,
                is_active  INTEGER DEFAULT 1,
                is_pinned  INTEGER DEFAULT 0
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
        """)
        # Idempotent migrations — safe to run on existing databases
        for migration in [
            "ALTER TABLE links ADD COLUMN is_pinned INTEGER DEFAULT 0",
            "ALTER TABLE links ADD COLUMN user_id INTEGER REFERENCES users(id)",
            "ALTER TABLE clicks ADD COLUMN ip_address TEXT",
            "ALTER TABLE clicks ADD COLUMN country TEXT",
        ]:
            try:
                conn.execute(migration)
            except Exception:
                pass

def seed_admin():
    """Upsert the admin account from env vars on every startup."""
    pw_hash = generate_password_hash(ADMIN_PASSWORD)
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with get_db() as conn:
        existing = conn.execute('SELECT id FROM users WHERE username=?', (ADMIN_USERNAME,)).fetchone()
        if existing:
            conn.execute('UPDATE users SET password_hash=?, is_admin=1 WHERE username=?',
                         (pw_hash, ADMIN_USERNAME))
        else:
            conn.execute(
                'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?,?,1,?)',
                (ADMIN_USERNAME, pw_hash, now)
            )

init_db()
seed_admin()


# ─────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated') or not session.get('user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated') or not session.get('user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# QR Generator
# ─────────────────────────────────────────────

def generate_qr_png(data: str, size: int = 300, fg=(0,0,0), bg=(255,255,255),
                    style: str = 'square', logo_bytes: bytes = None) -> bytes:
    """Generate QR PNG. Supports dot styles and logo overlay when qrcode[pil] is installed."""
    try:
        import qrcode as qrc
        from PIL import Image

        ec = qrc.constants.ERROR_CORRECT_H if logo_bytes else qrc.constants.ERROR_CORRECT_M
        qr = qrc.QRCode(error_correction=ec, border=2)
        qr.add_data(data)
        qr.make(fit=True)

        pil_img = None
        if style and style != 'square':
            try:
                from qrcode.image.styledpil import StyledPilImage
                from qrcode.image.styles.moduledrawers.pil import (
                    RoundedModuleDrawer, CircleModuleDrawer,
                    VerticalBarsDrawer, HorizontalBarsDrawer,
                )
                _drawers = {
                    'rounded':    RoundedModuleDrawer,
                    'dots':       CircleModuleDrawer,
                    'vertical':   VerticalBarsDrawer,
                    'horizontal': HorizontalBarsDrawer,
                }
                drawer_cls = _drawers.get(style)
                if drawer_cls:
                    qr_obj = qr.make_image(
                        image_factory=StyledPilImage,
                        module_drawer=drawer_cls(),
                        fill_color=fg,
                        back_color=bg,
                    )
                    tmp = io.BytesIO()
                    qr_obj.save(tmp, 'PNG')
                    tmp.seek(0)
                    pil_img = Image.open(tmp).convert('RGB')
            except (ImportError, Exception):
                pass

        if pil_img is None:
            qr_obj = qr.make_image(fill_color=fg, back_color=bg)
            tmp = io.BytesIO()
            qr_obj.save(tmp, 'PNG')
            tmp.seek(0)
            pil_img = Image.open(tmp).convert('RGB')

        pil_img = pil_img.resize((size, size), Image.LANCZOS)

        if logo_bytes:
            from PIL import ImageDraw
            logo = Image.open(io.BytesIO(logo_bytes)).convert('RGBA')
            logo_size = size // 4
            logo = logo.resize((logo_size, logo_size), Image.LANCZOS)

            # Erase a square tile at the centre to the background colour so
            # QR modules appear to wrap around the logo rather than being
            # covered by a floating patch.  A 2–3 px gutter keeps the nearest
            # module from butting right up against the logo edge.
            pad  = max(2, size // 100)
            zone = logo_size + pad * 2
            cx   = (size - zone) // 2
            cy   = (size - zone) // 2

            pil_img = pil_img.convert('RGBA')
            draw = ImageDraw.Draw(pil_img)
            draw.rectangle([cx, cy, cx + zone - 1, cy + zone - 1], fill=(*bg, 255))

            # Paste logo centred inside the cleared tile
            pil_img.paste(logo, (cx + pad, cy + pad), logo)
            pil_img = pil_img.convert('RGB')

        buf = io.BytesIO()
        pil_img.save(buf, 'PNG')
        return buf.getvalue()
    except ImportError:
        pass

    # Fallback pure-python PNG renderer (no styles/logo support)
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
    if 'google' in r:                                      return 'Google'
    if 'bing' in r:                                        return 'Bing'
    if 'facebook' in r or 'fb.com' in r:                  return 'Facebook'
    if 'twitter' in r or 't.co' in r or 'x.com' in r:    return 'Twitter/X'
    if 'linkedin' in r:                                    return 'LinkedIn'
    if 'reddit' in r:                                      return 'Reddit'
    if 'youtube' in r:                                     return 'YouTube'
    if 'instagram' in r:                                   return 'Instagram'
    return 'Other'

def get_client_ip():
    """Return the real client IP, honouring X-Forwarded-For from trusted proxies."""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''

def get_country_for_request():
    """Return a 2-letter ISO country code for the current request.

    Priority:
    1. CF-IPCountry header (Cloudflare — zero-latency, most reliable)
    2. ip-api.com free JSON API (1-second timeout, fails gracefully)
    Returns 'XX' if the IP is private/loopback, 'Unknown' on any failure.
    """
    import urllib.request as _ureq, json as _json

    cf = request.headers.get('CF-IPCountry', '').strip().upper()
    if cf and len(cf) == 2 and cf.isalpha() and cf != 'XX':
        return cf

    ip = get_client_ip()
    if not ip or ip in ('127.0.0.1', '::1'):
        return 'XX'
    # Skip RFC-1918 / loopback ranges — no point querying for private IPs
    try:
        import ipaddress
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return 'XX'
    except ValueError:
        pass
    try:
        req = _ureq.Request(
            f'http://ip-api.com/json/{ip}?fields=countryCode',
            headers={'User-Agent': 'QRknit/1.0'}
        )
        with _ureq.urlopen(req, timeout=1) as resp:
            data = _json.loads(resp.read())
        code = data.get('countryCode', '')
        return code if code else 'Unknown'
    except Exception:
        return 'Unknown'

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
    owner = conn.execute('SELECT username FROM users WHERE id=?', (row['user_id'],)).fetchone()
    return {
        'id':         row['id'],
        'code':       row['code'],
        'long_url':   row['long_url'],
        'title':      row['title'],
        'created_at': row['created_at'],
        'expires_at': row['expires_at'],
        'clicks':     row['clicks'],
        'is_active':  row['is_active'],
        'is_pinned':  row['is_pinned'],
        'short_url':  f"{BASE_URL}/{row['code']}",
        'qr_url':     f"{BASE_URL}/api/qr/{row['code']}",
        'tags':       get_link_tags(conn, row['id']),
        'created_by': owner['username'] if owner else None,
    }


# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────
# Health check (public — used by Docker healthcheck)
# ─────────────────────────────────────────────

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


@app.route('/api/config')
def get_config():
    """Public endpoint — exposes non-sensitive deployment config to the frontend."""
    return jsonify({'app_name': APP_NAME, 'base_url': BASE_URL})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid username or password'}), 401
    session.permanent = True
    session['authenticated'] = True
    session['user_id']  = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user['is_admin'])
    return jsonify({
        'authenticated': True,
        'id':       user['id'],
        'username': user['username'],
        'is_admin': bool(user['is_admin']),
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/auth/me', methods=['GET'])
def me():
    if session.get('authenticated') and session.get('user_id'):
        return jsonify({
            'authenticated': True,
            'id':       session.get('user_id'),
            'username': session.get('username'),
            'is_admin': session.get('is_admin', False),
        })
    return jsonify({'authenticated': False}), 401


# ─────────────────────────────────────────────
# Links
# ─────────────────────────────────────────────

@app.route('/api/shorten', methods=['POST'])
@login_required
def shorten():
    data        = request.get_json(silent=True) or {}
    long_url    = (data.get('url') or '').strip()
    custom_code = (data.get('custom_code') or '').strip()
    title       = (data.get('title') or '').strip()
    expires_at  = data.get('expires_at')
    tags        = data.get('tags', [])

    if not long_url:
        return jsonify({'error': 'URL is required'}), 400
    if not validate_url(long_url):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    if custom_code and not re.match(r'^[a-zA-Z0-9]{1,20}$', custom_code):
        return jsonify({'error': 'Custom code must be 1–20 alphanumeric characters'}), 400

    code = custom_code or generate_code(long_url)

    with get_db() as conn:
        existing = conn.execute('SELECT code FROM links WHERE code=?', (code,)).fetchone()
        if existing:
            if custom_code:
                return jsonify({'error': 'Custom code already taken'}), 409
            code = generate_code(long_url + str(time.time()))

        conn.execute(
            'INSERT INTO links (code,long_url,title,created_at,expires_at,user_id) VALUES (?,?,?,?,?,?)',
            (code, long_url, title or None,
             datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
             expires_at or None, session.get('user_id'))
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
    }), 201


@app.route('/api/links', methods=['GET'])
@login_required
def list_links():
    page        = int(request.args.get('page', 1))
    per_page    = min(int(request.args.get('per_page', 20)), 100)
    offset      = (page - 1) * per_page
    search      = (request.args.get('q') or '').strip()
    tag_filter  = (request.args.get('tag') or '').strip().lower()
    user_filter = (request.args.get('user') or '').strip()
    is_admin    = session.get('is_admin', False)
    user_id     = session.get('user_id')

    where_clauses = ['l.is_active=1']
    params = []

    # Non-admins see only their own links
    if not is_admin:
        where_clauses.append('l.user_id=?')
        params.append(user_id)
    elif user_filter:
        # Admins can filter down to a specific user's links
        where_clauses.append(
            'l.user_id=(SELECT id FROM users WHERE username=?)'
        )
        params.append(user_filter)

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
            f'SELECT * FROM links l WHERE {where_sql} ORDER BY l.is_pinned DESC, l.created_at DESC LIMIT ? OFFSET ?',
            params + [per_page, offset]
        ).fetchall()
        links = [format_link(r, conn) for r in rows]

    return jsonify({'links': links, 'total': total, 'page': page, 'per_page': per_page})


def _can_access_link(link):
    """Return True if the current session user may read/write this link."""
    if session.get('is_admin'):
        return True
    return link['user_id'] == session.get('user_id')

@app.route('/api/links/<code>', methods=['GET'])
@login_required
def link_detail(code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link or not _can_access_link(link):
            return jsonify({'error': 'Not found'}), 404
        return jsonify(format_link(link, conn))


@app.route('/api/links/<code>', methods=['PATCH'])
@login_required
def edit_link(code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
        if not link or not _can_access_link(link):
            return jsonify({'error': 'Not found'}), 404

        data = request.get_json(silent=True) or {}
        updates = {}
        if 'url' in data:
            url = data['url'].strip()
            if not validate_url(url): return jsonify({'error': 'Invalid URL'}), 400
            updates['long_url'] = url
        if 'title'      in data: updates['title']      = data['title'].strip() or None
        if 'expires_at' in data: updates['expires_at'] = data['expires_at'] or None
        if 'is_pinned'  in data: updates['is_pinned']  = 1 if data['is_pinned'] else 0

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
def delete_link(code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link or not _can_access_link(link):
            return jsonify({'error': 'Not found'}), 404
        conn.execute('UPDATE links SET is_active=0 WHERE code=?', (code,))
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Analytics
# ─────────────────────────────────────────────

@app.route('/api/links/<code>/analytics')
@login_required
def link_analytics(code):
    days = int(request.args.get('days', 30))
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link or not _can_access_link(link):
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

        # Hourly heatmap: 7 days-of-week × 24 hours
        # SQLite strftime('%w') returns 0=Sunday … 6=Saturday; we map to 0=Monday … 6=Sunday
        hourly_rows = conn.execute("""
            SELECT CAST(strftime('%w', clicked_at) AS INTEGER) as dow,
                   CAST(strftime('%H', clicked_at) AS INTEGER) as hr,
                   COUNT(*) as count
            FROM clicks WHERE link_id=? AND clicked_at>=?
            GROUP BY dow, hr
        """, (link_id, since)).fetchall()
        # heatmap[day_of_week 0=Mon][hour 0-23]
        heatmap = [[0] * 24 for _ in range(7)]
        for r in hourly_rows:
            mon_dow = (r['dow'] - 1) % 7  # 0=Sun→6, 1=Mon→0, …
            heatmap[mon_dow][r['hr']] = r['count']

        # Geographic breakdown
        country_rows = conn.execute("""
            SELECT COALESCE(NULLIF(country,''),'Unknown') as country, COUNT(*) as count
            FROM clicks WHERE link_id=? AND clicked_at>=?
            GROUP BY country ORDER BY count DESC LIMIT 20
        """, (link_id, since)).fetchall()
        countries = [{'country': r['country'], 'count': r['count']} for r in country_rows]

    return jsonify({
        'code': code, 'days': days,
        'total_clicks':  link['clicks'],
        'period_clicks': sum(d['clicks'] for d in daily),
        'daily': daily, 'referrers': referrers, 'devices': devices, 'browsers': browsers,
        'heatmap': heatmap, 'countries': countries,
    })


# ─────────────────────────────────────────────
# Click-event CSV export
# ─────────────────────────────────────────────

@app.route('/api/links/<code>/clicks/export')
@login_required
def export_clicks(code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=?', (code,)).fetchone()
        if not link or not _can_access_link(link):
            return jsonify({'error': 'Not found'}), 404
        rows = conn.execute(
            'SELECT clicked_at, referrer, user_agent, country FROM clicks '
            'WHERE link_id=? ORDER BY clicked_at DESC',
            (link['id'],)
        ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['timestamp', 'referrer', 'device', 'browser', 'country'])
    for row in rows:
        ua = row['user_agent'] or ''
        writer.writerow([
            row['clicked_at'],
            row['referrer'] or '',
            parse_device(ua),
            parse_browser(ua),
            row['country'] or '',
        ])
    return Response(
        buf.getvalue().encode('utf-8'),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="clicks-{code}.csv"'}
    )


# ─────────────────────────────────────────────
# Fetch Title
# ─────────────────────────────────────────────

@app.route('/api/fetch-title')
@login_required
def fetch_title():
    """Fetch the page title for a URL server-side (avoids CORS)."""
    import urllib.request as urllib_req
    url = (request.args.get('url') or '').strip()
    if not url or not validate_url(url):
        return jsonify({'title': ''})
    try:
        req = urllib_req.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; QRknit-title-fetcher/1.0)',
            'Accept': 'text/html',
        })
        with urllib_req.urlopen(req, timeout=5) as resp:
            ct = resp.headers.get('Content-Type', '')
            if 'html' not in ct.lower():
                return jsonify({'title': ''})
            html = resp.read(65536).decode('utf-8', errors='replace')
        # og:title (two attribute orderings)
        m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)["\']', html, re.I)
        if not m:
            m = re.search(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:title["\']', html, re.I)
        if m:
            return jsonify({'title': m.group(1).strip()[:200]})
        # Fall back to <title>
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m:
            return jsonify({'title': m.group(1).strip()[:200]})
        return jsonify({'title': ''})
    except Exception:
        return jsonify({'title': ''})


# ─────────────────────────────────────────────
# Tags & Stats
# ─────────────────────────────────────────────

@app.route('/api/tags')
@login_required
def list_tags():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT t.id, t.name, COUNT(lt.link_id) as link_count
            FROM tags t LEFT JOIN link_tags lt ON t.id=lt.tag_id
            GROUP BY t.id ORDER BY t.name
        """).fetchall()
    return jsonify({'tags': [dict(r) for r in rows]})


@app.route('/api/stats')
@login_required
def stats():
    is_admin = session.get('is_admin', False)
    user_id  = session.get('user_id')
    with get_db() as conn:
        if is_admin:
            total_links  = conn.execute('SELECT COUNT(*) FROM links WHERE is_active=1').fetchone()[0]
            total_clicks = conn.execute('SELECT COALESCE(SUM(clicks),0) FROM links WHERE is_active=1').fetchone()[0]
        else:
            total_links  = conn.execute('SELECT COUNT(*) FROM links WHERE is_active=1 AND user_id=?', (user_id,)).fetchone()[0]
            total_clicks = conn.execute('SELECT COALESCE(SUM(clicks),0) FROM links WHERE is_active=1 AND user_id=?', (user_id,)).fetchone()[0]

        since_7d  = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)).isoformat()
        since_30d = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)).isoformat()

        if is_admin:
            clicks_7d = conn.execute(
                'SELECT COUNT(*) FROM clicks c JOIN links l ON c.link_id=l.id '
                'WHERE c.clicked_at>=? AND l.is_active=1', (since_7d,)
            ).fetchone()[0]
            top_links = conn.execute(
                'SELECT code, long_url, title, clicks FROM links WHERE is_active=1 '
                'ORDER BY clicks DESC LIMIT 5'
            ).fetchall()
            daily_rows = conn.execute("""
                SELECT substr(c.clicked_at,1,10) as day, COUNT(*) as count
                FROM clicks c JOIN links l ON c.link_id=l.id
                WHERE c.clicked_at>=? AND l.is_active=1
                GROUP BY day ORDER BY day
            """, (since_30d,)).fetchall()
        else:
            clicks_7d = conn.execute(
                'SELECT COUNT(*) FROM clicks c JOIN links l ON c.link_id=l.id '
                'WHERE c.clicked_at>=? AND l.is_active=1 AND l.user_id=?', (since_7d, user_id)
            ).fetchone()[0]
            top_links = conn.execute(
                'SELECT code, long_url, title, clicks FROM links WHERE is_active=1 AND user_id=? '
                'ORDER BY clicks DESC LIMIT 5', (user_id,)
            ).fetchall()
            daily_rows = conn.execute("""
                SELECT substr(c.clicked_at,1,10) as day, COUNT(*) as count
                FROM clicks c JOIN links l ON c.link_id=l.id
                WHERE c.clicked_at>=? AND l.is_active=1 AND l.user_id=?
                GROUP BY day ORDER BY day
            """, (since_30d, user_id)).fetchall()

        daily_map = {r['day']: r['count'] for r in daily_rows}
        daily = [
            {'date': (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=29-i)).strftime('%Y-%m-%d'), 'clicks': 0}
            for i in range(30)
        ]
        for d in daily:
            d['clicks'] = daily_map.get(d['date'], 0)

    return jsonify({
        'total_links':  total_links,
        'total_clicks': total_clicks,
        'clicks_7d':    clicks_7d,
        'top_links':    [dict(r) for r in top_links],
        'daily':        daily,
    })


# ─────────────────────────────────────────────
# QR Routes
# ─────────────────────────────────────────────

@app.route('/api/qr/<code>')
def qr_code(code):
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size   = min(int(request.args.get('size', 300)), 1000)
    style  = request.args.get('style', 'square')
    with get_db() as conn:
        link = conn.execute('SELECT 1 FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404
    png = generate_qr_png(f"{BASE_URL}/{code}", size=size,
                          fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex), style=style)
    return Response(png, mimetype='image/png', headers={'Cache-Control': 'public, max-age=3600'})


@app.route('/api/qr/custom', methods=['GET'])
def qr_custom():
    url = request.args.get('url', '').strip()
    if not url or not validate_url(url):
        return jsonify({'error': 'Valid URL required'}), 400
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size   = min(int(request.args.get('size', 300)), 1000)
    style  = request.args.get('style', 'square')
    png = generate_qr_png(url, size=size, fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex), style=style)
    return Response(png, mimetype='image/png')


@app.route('/api/qr/custom', methods=['POST'])
def qr_custom_post():
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url or not validate_url(url):
        return jsonify({'error': 'Valid URL required'}), 400
    fg_hex = (data.get('fg') or '000000').lstrip('#')
    bg_hex = (data.get('bg') or 'ffffff').lstrip('#')
    size   = min(int(data.get('size', 300)), 1000)
    style  = data.get('style', 'square')
    logo_bytes = None
    logo_b64   = data.get('logo', '')
    if logo_b64:
        try:
            logo_bytes = base64.b64decode(logo_b64)
        except Exception:
            return jsonify({'error': 'Invalid logo data'}), 400
    png = generate_qr_png(url, size=size, fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex),
                          style=style, logo_bytes=logo_bytes)
    return Response(png, mimetype='image/png')


# ─────────────────────────────────────────────
# Bulk Operations
# ─────────────────────────────────────────────

@app.route('/api/links/bulk', methods=['POST'])
@login_required
def bulk_links():
    data   = request.get_json(silent=True) or {}
    action = data.get('action')
    codes  = data.get('codes', [])
    if not codes:
        return jsonify({'error': 'No codes provided'}), 400
    if action not in ('delete', 'tag', 'expire'):
        return jsonify({'error': 'Invalid action'}), 400

    is_admin = session.get('is_admin', False)
    user_id  = session.get('user_id')
    placeholders = ','.join('?' * len(codes))
    with get_db() as conn:
        if action == 'delete':
            if is_admin:
                conn.execute(f'UPDATE links SET is_active=0 WHERE code IN ({placeholders})', codes)
            else:
                conn.execute(
                    f'UPDATE links SET is_active=0 WHERE code IN ({placeholders}) AND user_id=?',
                    list(codes) + [user_id]
                )
            return jsonify({'deleted': len(codes)})

        elif action == 'tag':
            tags = data.get('tags', [])
            for code in codes:
                q = 'SELECT id,user_id FROM links WHERE code=? AND is_active=1'
                link = conn.execute(q, (code,)).fetchone()
                if link and (is_admin or link['user_id'] == user_id):
                    set_link_tags(conn, link['id'], tags)
            return jsonify({'tagged': len(codes)})

        elif action == 'expire':
            expires_at = data.get('expires_at') or None
            if is_admin:
                conn.execute(
                    f'UPDATE links SET expires_at=? WHERE code IN ({placeholders})',
                    [expires_at] + list(codes)
                )
            else:
                conn.execute(
                    f'UPDATE links SET expires_at=? WHERE code IN ({placeholders}) AND user_id=?',
                    [expires_at] + list(codes) + [user_id]
                )
            return jsonify({'updated': len(codes)})


# ─────────────────────────────────────────────
# CSV Export / Import
# ─────────────────────────────────────────────

@app.route('/api/links/export')
@login_required
def export_links():
    is_admin = session.get('is_admin', False)
    user_id  = session.get('user_id')
    with get_db() as conn:
        if is_admin:
            rows = conn.execute(
                'SELECT l.*, GROUP_CONCAT(t.name) as tag_names '
                'FROM links l '
                'LEFT JOIN link_tags lt ON l.id=lt.link_id '
                'LEFT JOIN tags t ON lt.tag_id=t.id '
                'WHERE l.is_active=1 '
                'GROUP BY l.id ORDER BY l.created_at DESC'
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT l.*, GROUP_CONCAT(t.name) as tag_names '
                'FROM links l '
                'LEFT JOIN link_tags lt ON l.id=lt.link_id '
                'LEFT JOIN tags t ON lt.tag_id=t.id '
                'WHERE l.is_active=1 AND l.user_id=? '
                'GROUP BY l.id ORDER BY l.created_at DESC',
                (user_id,)
            ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['code', 'short_url', 'long_url', 'title', 'tags', 'created_at', 'expires_at', 'clicks'])
    for row in rows:
        writer.writerow([
            row['code'],
            f"{BASE_URL}/{row['code']}",
            row['long_url'],
            row['title'] or '',
            row['tag_names'] or '',
            row['created_at'],
            row['expires_at'] or '',
            row['clicks'],
        ])
    return Response(
        buf.getvalue().encode('utf-8'),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{re.sub(r"[^a-z0-9]+", "-", APP_NAME.lower()).strip("-")}-export.csv"'}
    )


@app.route('/api/links/import', methods=['POST'])
@login_required
def import_links():
    data     = request.get_json(silent=True) or {}
    csv_text = (data.get('csv') or '').strip()
    if not csv_text:
        return jsonify({'error': 'No CSV data provided'}), 400

    reader  = csv.DictReader(io.StringIO(csv_text))
    created = 0
    errors  = []

    with get_db() as conn:
        for i, row in enumerate(reader, start=2):
            url = (row.get('url') or row.get('long_url') or '').strip()
            if not url:
                errors.append(f'Row {i}: missing URL'); continue
            if not validate_url(url):
                errors.append(f'Row {i}: invalid URL "{url[:50]}"'); continue

            custom_code = (row.get('custom_code') or row.get('code') or '').strip()
            title       = (row.get('title') or '').strip()
            expires_at  = (row.get('expires_at') or '').strip() or None
            tags_str    = (row.get('tags') or '').strip()
            tag_names   = [t.strip() for t in tags_str.split(',') if t.strip()] if tags_str else []

            if custom_code and not re.match(r'^[a-zA-Z0-9]{1,20}$', custom_code):
                errors.append(f'Row {i}: invalid code "{custom_code}"'); continue

            code = custom_code or generate_code(url)
            if conn.execute('SELECT 1 FROM links WHERE code=?', (code,)).fetchone():
                if custom_code:
                    errors.append(f'Row {i}: code "{custom_code}" already taken'); continue
                code = generate_code(url + str(time.time()))

            conn.execute(
                'INSERT INTO links (code, long_url, title, created_at, expires_at, user_id) VALUES (?,?,?,?,?,?)',
                (code, url, title or None,
                 datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), expires_at,
                 session.get('user_id'))
            )
            link_id = conn.execute('SELECT id FROM links WHERE code=?', (code,)).fetchone()['id']
            if tag_names:
                set_link_tags(conn, link_id, tag_names)
            created += 1

    return jsonify({'created': created, 'errors': errors})


# ─────────────────────────────────────────────
# Admin — User Management
# ─────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id, username, is_admin, created_at, '
            '(SELECT COUNT(*) FROM links WHERE user_id=users.id AND is_active=1) as link_count '
            'FROM users ORDER BY created_at ASC'
        ).fetchall()
    return jsonify({'users': [dict(r) for r in rows]})


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    is_admin = bool(data.get('is_admin', False))
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if not re.match(r'^[a-zA-Z0-9_.-]{2,32}$', username):
        return jsonify({'error': 'Username must be 2–32 alphanumeric/._- characters'}), 400
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
            return jsonify({'error': 'Username already taken'}), 409
        conn.execute(
            'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?,?,?,?)',
            (username, generate_password_hash(password), 1 if is_admin else 0,
             datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        )
        user = conn.execute('SELECT id, username, is_admin, created_at FROM users WHERE username=?',
                            (username,)).fetchone()
    return jsonify(dict(user)), 201


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Not found'}), 404
        conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    return jsonify({'success': True})


@app.route('/api/admin/users/<int:user_id>/password', methods=['PATCH'])
@admin_required
def admin_change_password(user_id):
    data     = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    if not password:
        return jsonify({'error': 'Password required'}), 400
    with get_db() as conn:
        if not conn.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
            return jsonify({'error': 'Not found'}), 404
        conn.execute('UPDATE users SET password_hash=? WHERE id=?',
                     (generate_password_hash(password), user_id))
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Redirect
# ─────────────────────────────────────────────

@app.route('/<code>')
def redirect_link(code):
    if code in ('static', 'api', 'favicon.ico'):
        return 'Not found', 404
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code=? AND is_active=1', (code,)).fetchone()
        if not link:
            return redirect('/?error=not_found')
        if link['expires_at'] and link['expires_at'] < datetime.now(timezone.utc).replace(tzinfo=None).isoformat():
            return redirect('/?error=expired')
        country    = get_country_for_request()
        client_ip  = get_client_ip()
        conn.execute(
            'INSERT INTO clicks (link_id,clicked_at,referrer,user_agent,ip_address,country) VALUES (?,?,?,?,?,?)',
            (link['id'], datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
             request.referrer, request.headers.get('User-Agent','')[:500],
             client_ip[:45], country)
        )
        conn.execute('UPDATE links SET clicks=clicks+1 WHERE id=?', (link['id'],))
        return redirect(link['long_url'], code=301)


# ─────────────────────────────────────────────
# Frontend routes
# ─────────────────────────────────────────────

@app.route('/')
def landing():
    with open(os.path.join(os.path.dirname(__file__), 'landing.html')) as f:
        return f.read()

@app.route('/app', defaults={'subpath': ''})
@app.route('/app/<path:subpath>')
def app_frontend(subpath):
    with open(os.path.join(os.path.dirname(__file__), 'index.html')) as f:
        return f.read()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port,
            debug=os.environ.get('DEBUG', 'false').lower() == 'true')
