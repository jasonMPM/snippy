# QRknit — URL Shortener & QR Code Generator

A self-hosted URL shortener with QR code generation, click analytics, and tag-based link organization. Built on Python/Flask + SQLite. Runs as a single Docker container — designed for Unraid but works anywhere Docker runs.

- **Multi-user** — admin account seeded from env vars; admin can create/delete additional accounts via the UI
- **Per-user isolation** — each user sees only their own links; admin sees all
- **Zero external dependencies** — SQLite, no Redis, no Postgres, no message queue
- **Single-file frontend** — all CSS and JS are inline; no build step, no node_modules

---

## 📍 Milestones

### Completed

| # | Milestone | Highlights |
|---|---|---|
| 1 | **Core MVP** | URL shortening (random & custom codes), QR generation, click tracking, link expiry, dashboard stats, dark-mode SPA |
| 2 | **Analytics & Management** | Per-link daily click charts, referrer & device breakdowns, link editing, search/filter, tags |
| 3 | **Auth** | Session-cookie auth, 30-day HttpOnly cookie, works behind Cloudflare and Nginx Proxy Manager |
| 4 | **QR & Bulk Tools** | QR logo overlay, dot-shape presets, bulk delete/tag/expire, CSV import & export |
| 5 | **UX Improvements** | Pinned links, one-click copy, auto-fetch page title, inline QR thumbnail, copy QR to clipboard |
| 6 | **Deployment Portability** | `APP_NAME` & `BASE_URL` env vars, `/api/config` endpoint, all hardcoded domains removed |
| 7 | **UI Polish** | Teal/blue accent palette, gradient hero & buttons, improved text contrast |
| 8 | **Multi-user** | Per-user accounts, admin user-management panel, `ADMIN_USERNAME` env var, username + password login |
| 9 | **Analytics Deep-Dive** | Geographic breakdown (country via CF-IPCountry + ip-api.com), hourly 7×24 heatmap, dashboard-wide 30-day click chart, per-link raw click-event CSV export |

### Upcoming

| # | Milestone | Planned features |
|---|---|---|
| 10 | **Power Features** | API key auth, password-protected links, UTM parameter builder, custom 404/expired pages |
| 11 | **Link Organisation** | Folders/groups, duplicate link, link health checks, per-link redirect type (301 vs 302) |

---

## 🚀 Installation

### Prerequisites

- Docker installed and running
- A domain or subdomain pointed at your server (for public access)

Generate a strong `SECRET_KEY` before you begin:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

### Option A — Docker run (quickest)

**1. Get the source**
```bash
git clone https://github.com/jasonMPM/qrknit.git
cd qrknit
```

**2. Build the image**
```bash
docker build -t qrknit:latest .
```

**3. Run the container**
```bash
docker run -d \
  --name qrknit \
  --restart unless-stopped \
  -p 5000:5000 \
  -v qrknit-data:/app/data \
  -e BASE_URL=https://yourdomain.com \
  -e APP_NAME=My.Links \
  -e SECRET_KEY=your-generated-key-here \
  -e ADMIN_PASSWORD=your-strong-password \
  qrknit:latest
```

Open `http://localhost:5000` (or your domain) and log in with `admin` / your `ADMIN_PASSWORD`.

---

### Option B — Docker Compose

**1. Get the source**
```bash
git clone https://github.com/jasonMPM/qrknit.git
cd qrknit
```

**2. Edit `docker-compose.yml`** — set at minimum:
```yaml
- BASE_URL=https://yourdomain.com
- APP_NAME=My.Links
- SECRET_KEY=your-generated-key-here
- ADMIN_PASSWORD=your-strong-password
```

**3. Build and start**
```bash
docker compose up -d --build
```

---

### Option C — Unraid (fresh install)

**Step 1 — Get the source onto Unraid**

Open the Unraid terminal and run:
```bash
cd /mnt/user/appdata
git clone https://github.com/jasonMPM/qrknit.git qrknit-src
```

Or upload the source files manually to `/mnt/user/appdata/qrknit-src/`.

**Step 2 — Build the image**
```bash
cd /mnt/user/appdata/qrknit-src
docker build -t qrknit:latest .
```

> Once QRknit is on Docker Hub, you can skip Steps 1–2 and pull the image directly.

**Step 3 — Add the container in the Unraid Docker UI**

Go to **Docker** tab → **Add Container** and fill in:

| Field | Value |
|---|---|
| **Name** | `qrknit` |
| **Repository** | `qrknit:latest` |
| **Network Type** | `br0` (macvlan) or `Bridge` |
| **Port Mapping** | Host `5000` → Container `5000` *(not needed for macvlan)* |
| **Path (Volume)** | Host `/mnt/user/appdata/qrknit` → Container `/app/data` |

Add the following **Environment Variables**:

| Variable | Value | Notes |
|---|---|---|
| `BASE_URL` | `https://yourdomain.com` | Your public domain or subdomain |
| `APP_NAME` | `My.Links` | Display name shown in the UI — names with a dot (e.g. `to.mysite.io`) are split and styled automatically |
| `SECRET_KEY` | *(generated above)* | **Required** — signs session cookies |
| `ADMIN_PASSWORD` | *(your password)* | **Required** — admin account password |
| `ADMIN_USERNAME` | `admin` | Admin username (default: `admin`) |
| `COOKIE_SECURE` | `false` | Keep `false` behind Cloudflare or NPM. Set `true` only if Flask receives HTTPS directly. |
| `DEBUG` | `false` | Keep `false` in production |

Click **Apply**.

**Step 4 — Set up a reverse proxy** *(optional but recommended)*

**Cloudflare:**
- Point your DNS A record to your Unraid IP
- Enable **Always Use HTTPS** in Cloudflare dashboard (SSL/TLS → Edge Certificates)
- Keep `COOKIE_SECURE=false` — Cloudflare terminates TLS before Flask sees the request

**Nginx Proxy Manager:**
- Add a proxy host: your domain → `unraid-lan-ip:5000`
- Issue a Let's Encrypt certificate on the SSL tab
- Keep `COOKIE_SECURE=false` — same reason as Cloudflare

**Step 5 — Verify**
```bash
docker inspect --format='{{.State.Health.Status}}' qrknit
# healthy

curl https://yourdomain.com/api/health
# {"status":"ok"}
```

---

## 🔄 Updating

Your data lives in the Docker volume and is preserved across updates.

**Docker / Docker Compose:**
```bash
cd /path/to/qrknit-src
git pull
docker build -t qrknit:latest .
docker stop qrknit && docker rm qrknit
# Re-run the same docker run command from installation
```

**Unraid:**
```bash
cd /mnt/user/appdata/qrknit-src
git pull
docker build -t qrknit:latest .
```
Then click **Force Update** on the container in the Docker tab.

> Sessions survive restarts as long as `SECRET_KEY` stays the same. Changing `SECRET_KEY` invalidates all active sessions — users will need to log in again.

---

## 🗂 Project Structure

```
qrknit/
├── app.py              # Flask backend — all routes and logic
├── index.html          # Single-page frontend (inline CSS + JS, served by Flask)
├── requirements.txt    # Python dependencies
├── Dockerfile          # Multi-stage Docker build
├── docker-compose.yml  # For non-Unraid deployments
├── .dockerignore
└── README.md
```

---

## 🔌 API Reference

All write endpoints require an active session (log in via the web UI or `POST /api/auth/login`).

### Auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | — | Login — `{"username": "...", "password": "..."}`, sets session cookie |
| POST | `/api/auth/logout` | ✓ | Clear session |
| GET | `/api/auth/me` | ✓ | Returns `{"authenticated": true, "username": "...", "is_admin": bool}` |

### Links

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/shorten` | ✓ | Create a short link |
| GET | `/api/links` | ✓ | List links — supports `?q=`, `?tag=`, `?page=`, `?per_page=` |
| GET | `/api/links/:code` | ✓ | Link detail |
| PATCH | `/api/links/:code` | ✓ | Edit link — `url`, `title`, `expires_at`, `tags`, `is_pinned` |
| DELETE | `/api/links/:code` | ✓ | Delete link |
| GET | `/api/links/:code/analytics` | ✓ | Click analytics — supports `?days=7\|30\|90` |

### Utilities

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/stats` | ✓ | Total links, total clicks, clicks/7d, top links |
| GET | `/api/tags` | ✓ | All tags with link counts |
| GET | `/api/fetch-title` | ✓ | Server-side page title fetch — `?url=`. Returns `{"title":"…"}` |
| GET | `/api/qr/:code` | — | QR PNG for a short link |
| GET | `/api/qr/custom` | — | QR PNG for any URL — `?url=`, `?fg=`, `?bg=`, `?size=`, `?style=` |
| POST | `/api/qr/custom` | — | QR PNG with logo overlay — `{url, fg, bg, size, style, logo}` (logo as base64) |
| POST | `/api/links/bulk` | ✓ | Bulk operations — `{action: "delete"\|"tag"\|"expire", codes: […]}` |
| GET | `/api/links/export` | ✓ | Download all links as CSV |
| POST | `/api/links/import` | ✓ | Import links from CSV — `{csv: "…"}` |
| GET | `/api/health` | — | Health check — `{"status":"ok"}` |
| GET | `/:code` | — | Redirect to destination URL |

### Admin

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/admin/users` | Admin | List all users with link counts |
| POST | `/api/admin/users` | Admin | Create user — `{username, password, is_admin}` |
| DELETE | `/api/admin/users/:id` | Admin | Delete user (cannot delete self) |
| PATCH | `/api/admin/users/:id/password` | Admin | Change user password — `{password}` |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:5000` | Public URL of your instance — used in short links and QR codes |
| `APP_NAME` | `My.Links` | Display name in the header, hero, login modal, and page title. Names with a dot are split and styled automatically. |
| `SECRET_KEY` | *(required)* | Signs session cookies — use a long random string |
| `ADMIN_PASSWORD` | *(required)* | Admin account password — upserted on every startup |
| `ADMIN_USERNAME` | `admin` | Admin account username |
| `PORT` | `5000` | Port Gunicorn listens on |
| `DEBUG` | `false` | Flask debug mode — keep `false` in production |
| `COOKIE_SECURE` | `false` | Set `true` only if Flask receives HTTPS directly (not behind a proxy) |
| `DB_PATH` | `/app/data/qrknit.db` | SQLite file path — leave as-is when using a Docker volume |
