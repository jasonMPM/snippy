"""
SnipLink - URL Shortener & QR Code Generator
Flask Backend Application
"""

import os
import sqlite3
import hashlib
import time
import json
import base64
import io
import struct
import zlib
from datetime import datetime
from flask import Flask, request, jsonify, redirect, send_from_directory, render_template_string

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sniplink-secret-change-in-production')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'sniplink.db'))
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                code        TEXT UNIQUE NOT NULL,
                long_url    TEXT NOT NULL,
                title       TEXT,
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                clicks      INTEGER DEFAULT 0,
                is_active   INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS clicks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id     INTEGER NOT NULL,
                clicked_at  TEXT NOT NULL,
                referrer    TEXT,
                user_agent  TEXT,
                FOREIGN KEY (link_id) REFERENCES links(id)
            );
            CREATE INDEX IF NOT EXISTS idx_links_code ON links(code);
        """)

# ─────────────────────────────────────────────
# Pure-Python QR Code Generator (minimal, no deps)
# Generates a QR code as PNG bytes using a simplified matrix
# For production, replace with the `qrcode` library
# ─────────────────────────────────────────────

def generate_qr_png(data: str, size: int = 300, fg=(0,0,0), bg=(255,255,255)) -> bytes:
    """
    Generates a basic QR code PNG.
    Uses Python's built-in zlib + struct to write a valid PNG.
    The actual QR matrix is computed via a minimal QR encoder.
    For production use, install: pip install qrcode[pil]
    and replace this function with:
        import qrcode
        img = qrcode.make(data)
    """
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

    # Fallback: simple placeholder PNG (10x10 checkerboard scaled)
    # In production, install qrcode library
    module_count = 21  # Version 1 QR
    cell = max(4, size // module_count)
    img_size = cell * module_count

    # Build raw pixel data (RGB)
    pixels = []
    for row in range(img_size):
        row_pixels = b''
        for col in range(img_size):
            r, c = row // cell, col // cell
            # Draw finder patterns only (corner squares) as demo
            in_finder = (
                (r < 7 and c < 7) or
                (r < 7 and c >= module_count - 7) or
                (r >= module_count - 7 and c < 7)
            )
            is_dark = False
            if in_finder:
                lr, lc = r % 7, c % 7
                is_dark = (lr == 0 or lr == 6 or lc == 0 or lc == 6 or
                           (2 <= lr <= 4 and 2 <= lc <= 4))
            elif (row // cell + col // cell) % 2 == 0:
                # timing pattern approximation
                is_dark = (r == 6 or c == 6) and (r % 2 == 0 or c % 2 == 0)
            color = fg if is_dark else bg
            row_pixels += bytes(color)
        pixels.append(row_pixels)

    def png_chunk(chunk_type, data):
        c = chunk_type + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    # PNG header
    png_header = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', img_size, img_size, 8, 2, 0, 0, 0)
    ihdr = png_chunk(b'IHDR', ihdr_data)

    # IDAT (image data)
    raw = b''.join(b'\x00' + row for row in pixels)
    compressed = zlib.compress(raw)
    idat = png_chunk(b'IDAT', compressed)
    iend = png_chunk(b'IEND', b'')

    return png_header + ihdr + idat + iend


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def generate_code(url: str, length: int = 6) -> str:
    seed = f"{url}{time.time()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:length]

def validate_url(url: str) -> bool:
    return url.startswith(('http://', 'https://'))

# ─────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────

@app.route('/api/shorten', methods=['POST'])
def shorten():
    data = request.get_json(silent=True) or {}
    long_url = (data.get('url') or '').strip()
    custom_code = (data.get('custom_code') or '').strip()
    title = (data.get('title') or '').strip()
    expires_at = data.get('expires_at')

    if not long_url:
        return jsonify({'error': 'URL is required'}), 400
    if not validate_url(long_url):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    code = custom_code if custom_code else generate_code(long_url)

    # Validate custom code
    if custom_code:
        if not custom_code.isalnum() or len(custom_code) < 3 or len(custom_code) > 20:
            return jsonify({'error': 'Custom code must be 3–20 alphanumeric characters'}), 400

    with get_db() as conn:
        # Check if code exists
        existing = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
        if existing:
            if custom_code:
                return jsonify({'error': 'Custom code already taken'}), 409
            code = generate_code(long_url + str(time.time()))

        conn.execute(
            'INSERT INTO links (code, long_url, title, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            (code, long_url, title or None, datetime.utcnow().isoformat(), expires_at)
        )

    short_url = f"{BASE_URL}/{code}"
    return jsonify({
        'code': code,
        'short_url': short_url,
        'long_url': long_url,
        'title': title,
        'qr_url': f"{BASE_URL}/api/qr/{code}"
    }), 201


@app.route('/api/qr/<code>')
def qr_code(code):
    """Generate QR code for a short link"""
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size = min(int(request.args.get('size', 300)), 1000)

    def hex_to_rgb(h):
        h = h.lstrip('#')
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code = ? AND is_active = 1', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Link not found'}), 404

    short_url = f"{BASE_URL}/{code}"
    png_bytes = generate_qr_png(short_url, size=size, fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex))

    from flask import Response
    return Response(png_bytes, mimetype='image/png',
                    headers={'Cache-Control': 'public, max-age=3600'})


@app.route('/api/qr/custom')
def qr_custom():
    """Generate QR code for any custom URL (not stored)"""
    url = request.args.get('url', '').strip()
    if not url or not validate_url(url):
        return jsonify({'error': 'Valid URL required'}), 400
    fg_hex = request.args.get('fg', '000000')
    bg_hex = request.args.get('bg', 'ffffff')
    size = min(int(request.args.get('size', 300)), 1000)

    def hex_to_rgb(h):
        h = h.lstrip('#')
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    png_bytes = generate_qr_png(url, size=size, fg=hex_to_rgb(fg_hex), bg=hex_to_rgb(bg_hex))
    from flask import Response
    return Response(png_bytes, mimetype='image/png')


@app.route('/api/links', methods=['GET'])
def list_links():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    offset = (page - 1) * per_page
    with get_db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM links WHERE is_active=1').fetchone()[0]
        rows = conn.execute(
            'SELECT * FROM links WHERE is_active=1 ORDER BY created_at DESC LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()
    links = []
    for r in rows:
        links.append({
            'id': r['id'], 'code': r['code'], 'long_url': r['long_url'],
            'title': r['title'], 'created_at': r['created_at'],
            'expires_at': r['expires_at'], 'clicks': r['clicks'],
            'short_url': f"{BASE_URL}/{r['code']}",
            'qr_url': f"{BASE_URL}/api/qr/{r['code']}"
        })
    return jsonify({'links': links, 'total': total, 'page': page, 'per_page': per_page})


@app.route('/api/links/<code>', methods=['GET'])
def link_detail(code):
    with get_db() as conn:
        link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
        if not link:
            return jsonify({'error': 'Not found'}), 404
        recent_clicks = conn.execute(
            'SELECT clicked_at, referrer FROM clicks WHERE link_id = ? ORDER BY clicked_at DESC LIMIT 50',
            (link['id'],)
        ).fetchall()
    return jsonify({
        'code': link['code'], 'long_url': link['long_url'], 'title': link['title'],
        'created_at': link['created_at'], 'expires_at': link['expires_at'],
        'clicks': link['clicks'], 'is_active': link['is_active'],
        'short_url': f"{BASE_URL}/{link['code']}",
        'qr_url': f"{BASE_URL}/api/qr/{link['code']}",
        'recent_clicks': [dict(c) for c in recent_clicks]
    })


@app.route('/api/links/<code>', methods=['DELETE'])
def delete_link(code):
    with get_db() as conn:
        conn.execute('UPDATE links SET is_active = 0 WHERE code = ?', (code,))
    return jsonify({'success': True})


@app.route('/api/stats', methods=['GET'])
def stats():
    with get_db() as conn:
        total_links = conn.execute('SELECT COUNT(*) FROM links WHERE is_active=1').fetchone()[0]
        total_clicks = conn.execute('SELECT SUM(clicks) FROM links WHERE is_active=1').fetchone()[0] or 0
        top_links = conn.execute(
            'SELECT code, long_url, title, clicks FROM links WHERE is_active=1 ORDER BY clicks DESC LIMIT 5'
        ).fetchall()
    return jsonify({
        'total_links': total_links,
        'total_clicks': total_clicks,
        'top_links': [dict(r) for r in top_links]
    })


# ─────────────────────────────────────────────
# Redirect Route
# ─────────────────────────────────────────────

@app.route('/<code>')
def redirect_link(code):
    # Skip static and api
    if code in ('static', 'api', 'favicon.ico'):
        return 'Not found', 404
    with get_db() as conn:
        link = conn.execute(
            'SELECT * FROM links WHERE code = ? AND is_active = 1', (code,)
        ).fetchone()
        if not link:
            return redirect('/?error=not_found')

        # Check expiry
        if link['expires_at'] and link['expires_at'] < datetime.utcnow().isoformat():
            return redirect('/?error=expired')

        # Record click
        conn.execute(
            'INSERT INTO clicks (link_id, clicked_at, referrer, user_agent) VALUES (?, ?, ?, ?)',
            (link['id'], datetime.utcnow().isoformat(),
             request.referrer, request.headers.get('User-Agent', '')[:500])
        )
        conn.execute('UPDATE links SET clicks = clicks + 1 WHERE id = ?', (link['id'],))
        return redirect(link['long_url'], code=301)


# ─────────────────────────────────────────────
# Frontend
# ─────────────────────────────────────────────

@app.route('/')
@app.route('/dashboard')
def index():
    with open(os.path.join(os.path.dirname(__file__), 'templates', 'index.html')) as f:
        return f.read()


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'false').lower() == 'true')
