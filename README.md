# to.ALWISP — URL Shortener & QR Code Generator

A self-hosted URL shortener with QR code generation, click analytics, and tag-based link organization. Built on Python/Flask + SQLite. Runs as a Docker container — designed for Unraid but works anywhere Docker runs.

Multi-user: admin account is seeded from env vars on startup. Admin can create/delete additional user accounts via the UI. Each user sees only their own links; admin sees all.

---

## 📍 Project Roadmap

### ✅ Phase 1 — Core MVP (Complete)
- [x] URL shortening with random or custom codes
- [x] Click tracking (timestamp, referrer, user-agent)
- [x] QR code generation per short link (backend-rendered PNG)
- [x] Custom QR generator with color and size controls
- [x] Link expiration support
- [x] Dashboard with stats (total links, total clicks, avg clicks/link)
- [x] Link management (view, copy, delete)
- [x] Dark-mode single-page frontend
- [x] SQLite database (zero config, single file, Docker volume)
- [x] Docker image with multi-stage build
- [x] Unraid-ready container config

### ✅ Phase 2 — Analytics & Management (Complete)
- [x] Per-link click analytics chart (daily clicks over time)
- [x] Referrer breakdown (Google, Facebook, Twitter/X, Direct, etc.)
- [x] Device/browser breakdown from User-Agent parsing
- [x] Link editing (change destination URL, title, expiry)
- [x] Search/filter links in dashboard
- [x] Link tags/categories

### ✅ Phase 3 — Auth (Complete)
- [x] Single-admin password protection via `ADMIN_PASSWORD` env var
- [x] Flask signed session cookie (30-day, HttpOnly)
- [x] No accounts, no registration, no tokens to expire
- [x] Works correctly behind Cloudflare and Nginx Proxy Manager

### ✅ Phase 4 — QR & Link Management (Complete)
- [x] QR code logo/icon embedding (upload image, centered overlay)
- [x] QR dot shape presets (rounded, dots, vertical bars, horizontal bars)
- [x] Bulk link operations (bulk delete, bulk tag, bulk expire)
- [x] CSV import — paste or upload a spreadsheet of URLs to shorten in batch
- [x] CSV export — download all links + stats
- [ ] Link folders/groups — deferred to a dedicated organisation phase

### ✅ Phase 5 — UX Improvements (Complete)
- [x] Pin / favorites — star any link to float it to the top of the dashboard list
- [x] One-click copy — inline copy button on every link row, no expand needed
- [x] Auto-fetch title — URL field blur triggers a server-side title fetch (`og:title` → `<title>`); pre-fills the title field when empty (works in both the Shorten form and the edit form)
- [x] Inline QR thumbnail — 80px QR preview inside every expanded link row (lazy-loaded)
- [x] Copy QR to clipboard — writes QR PNG to clipboard via Clipboard API; button is only rendered on browsers that support it (Chrome/Edge), hidden elsewhere
- [x] Customize QR shortcut — jump directly to the QR tab with the short URL pre-filled

### ✅ Phase 6 — Deployment Portability (Complete)
- [x] `APP_NAME` env var — display name applied to header, hero, login modal, and page title at runtime; no rebuild needed
- [x] Names with a dot (e.g. `go.mysite.io`) are split and styled automatically; plain names work too
- [x] `BASE_URL` Dockerfile default changed from a specific domain to `http://localhost:5000`
- [x] `/api/config` public endpoint exposes `app_name` and `base_url` to the frontend
- [x] Dockerfile healthcheck fixed to use public `/api/health` (was hitting auth-required `/api/stats`)
- [x] CSV export filename derived from `APP_NAME` slug (e.g. `to-alwisp-export.csv`)
- [x] All hardcoded domain references removed from `docker-compose.yml` and `Dockerfile`

### ✅ Phase 7 — UI Polish (Complete)
- [x] Accent colour changed from green to teal/blue palette (`#00b8d4` → `#1a52c8`) matched to brand image
- [x] Teal → blue gradient applied to hero title, primary buttons, and background ambient glow
- [x] Text contrast improved — `--text` and `--muted` tokens nudged brighter across all 20 hardcoded rgba instances

---

## 💡 Suggested Next Phases

### Phase 8 — Analytics Deep-Dive
Upgrade the analytics story from basic charts to actionable data.
- [ ] **Geographic breakdown** — country/city from click IP via a lightweight free API (e.g. `ip-api.com`); stored at click time, shown as a flag + bar chart
- [ ] **Hourly heatmap** — 7×24 grid showing click density by day-of-week and hour-of-day; reveals when your audience is active
- [ ] **Dashboard-wide click chart** — aggregate daily clicks across all links on the main dashboard, not just per link
- [ ] **Click data CSV export** — download raw click events (timestamp, referrer, country, device) per link or for all links

### Phase 9 — Power Features
Features for more advanced / programmatic use.
- [ ] **API key authentication** — generate a Bearer token in the UI; allows curl / scripts / integrations to use the API without a browser session
- [ ] **Password-protected links** — optional passphrase on a short link; visitors see a prompt before the redirect fires
- [ ] **UTM parameter builder** — integrated into the create form; pick source/medium/campaign and have them appended to the destination URL automatically
- [ ] **Custom 404 / expired pages** — branded HTML page instead of a bare redirect to `/?error=`; configurable message via env var

### Phase 10 — Link Organisation
Structure and housekeeping for large link collections.
- [ ] **Folders / groups** — logical containers for links (the item deferred from Phase 4); shown as a collapsible sidebar filter
- [ ] **Duplicate link** — clone an existing link with a new code in one click; useful for A/B variants
- [ ] **Link health check** — background job that periodically fetches destination URLs and flags 4xx/5xx responses with a warning badge
- [ ] **Custom redirect type** — choose 301 (permanent, browser-cached) vs 302 (temporary) per link; currently all links are 301

### ✅ Phase 8 — Multi-user (Complete)
- [x] Per-user accounts with password — admin creates accounts directly via Users tab, no self-registration
- [x] Each user sees only their own links; admin sees all
- [x] Admin dashboard for user management (create, delete, change password)
- [x] `ADMIN_USERNAME` env var (default: `admin`) — admin account upserted from env vars on every startup
- [x] Login form updated to username + password
- [x] User badge in header showing logged-in username and role
- [x] Existing links (pre-migration) remain visible to admin; new links are owned by the creating user

---

## 🚀 Setup

### Required environment variables

| Variable | Description |
|---|---|
| `SECRET_KEY` | Long random string — signs session cookies |
| `ADMIN_PASSWORD` | Password for the admin account |
| `ADMIN_USERNAME` | Username for the admin account (default: `admin`) |

Generate a strong `SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Docker run

```bash
docker run -d \
  --name sniplink \
  --restart unless-stopped \
  -p 5000:5000 \
  -v sniplink-data:/app/data \
  -e BASE_URL=https://yourdomain.com \
  -e APP_NAME=to.ALWISP \
  -e SECRET_KEY=your-generated-key-here \
  -e ADMIN_PASSWORD=your-strong-password \
  sniplink:latest
```

### Docker Compose

```bash
# Edit docker-compose.yml — set BASE_URL, SECRET_KEY, ADMIN_PASSWORD
docker compose up -d --build
```

---

## 🖥 Unraid Setup

### Step 1 — Build the image

**Option A: Build directly on Unraid**
```bash
cd /mnt/user/appdata/sniplink-src
docker build -t sniplink:latest .
```

**Option B: Push to Docker Hub**
```bash
docker build -t yourdockerhubusername/sniplink:latest .
docker push yourdockerhubusername/sniplink:latest
```

### Step 2 — Add container in Unraid Docker UI

1. Go to **Docker** tab → **Add Container**
2. Fill in:

| Field | Value |
|---|---|
| **Name** | `sniplink` |
| **Repository** | `sniplink:latest` or your Docker Hub image |
| **Network Type** | `Bridge` |
| **Port Mapping** | Host `5000` → Container `5000` |
| **Path (Volume)** | Host `/mnt/user/appdata/sniplink` → Container `/app/data` |

3. Add **Environment Variables**:

| Key | Value | Notes |
|---|---|---|
| `BASE_URL` | `https://yourdomain.com` | Your public domain or subdomain |
| `APP_NAME` | `to.ALWISP` | Display name in the UI (e.g. `go.mysite.io`) |
| `SECRET_KEY` | *(long random string)* | **Required** |
| `ADMIN_PASSWORD` | *(your password)* | **Required** |
| `COOKIE_SECURE` | `false` | Keep `false` when behind a proxy (Cloudflare, NPM). Set `true` only if Flask receives HTTPS directly. |
| `DEBUG` | `false` | Keep false in production |

### Step 3 — Reverse proxy

#### Cloudflare (current setup)
- Point your DNS A record to your public IP
- Enable **Always Use HTTPS** in Cloudflare dashboard (SSL/TLS → Edge Certificates) to ensure all browsers land on HTTPS
- Keep `COOKIE_SECURE=false` — Cloudflare terminates TLS before the request reaches Flask

#### Nginx Proxy Manager
- Add a proxy host: domain → your Unraid LAN IP:5000
- Request a Let's Encrypt certificate on the SSL tab
- Keep `COOKIE_SECURE=false` — same reason as Cloudflare

### Step 4 — Verify

```bash
docker inspect --format='{{.State.Health.Status}}' sniplink
# Should return: healthy

curl https://yourdomain.com/api/health
# {"status":"ok"}
```

---

## 🗂 Project Structure

```
sniplink/
├── app.py              # Flask backend — all routes and logic
├── index.html          # Single-page frontend (served by Flask)
├── requirements.txt    # Python dependencies
├── Dockerfile          # Multi-stage Docker build
├── docker-compose.yml  # For non-Unraid deployments
├── .dockerignore
└── README.md
```

---

## 🔌 API Reference

All write endpoints require an active session (log in via the web UI first, or POST `/api/auth/login`).

### Auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | — | Login with `{"username": "...", "password": "..."}`, sets session cookie |
| POST | `/api/auth/logout` | ✓ | Clear session |
| GET | `/api/auth/me` | ✓ | Returns `{"authenticated": true, "username": "...", "is_admin": bool}` |

### Links

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/shorten` | ✓ | Shorten a URL |
| GET | `/api/links` | ✓ | List links (supports `?q=`, `?tag=`, `?page=`, `?per_page=`) |
| GET | `/api/links/:code` | ✓ | Link detail |
| PATCH | `/api/links/:code` | ✓ | Edit link (`url`, `title`, `expires_at`, `tags`, `is_pinned`) |
| DELETE | `/api/links/:code` | ✓ | Delete link |
| GET | `/api/links/:code/analytics` | ✓ | Click analytics (supports `?days=7\|30\|90`) |

### Utilities

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/stats` | ✓ | Total links, total clicks, clicks/7d, top links |
| GET | `/api/tags` | ✓ | All tags with link counts |
| GET | `/api/fetch-title` | ✓ | Fetch page title for a URL server-side (`?url=`). Returns `{"title":"…"}`. Tries `og:title` then `<title>`. |
| GET | `/api/qr/:code` | — | QR PNG for a short link |
| GET | `/api/qr/custom` | — | QR PNG for any URL (`?url=`, `?fg=`, `?bg=`, `?size=`, `?style=`) |
| POST | `/api/qr/custom` | — | QR PNG with logo overlay (`{url, fg, bg, size, style, logo}` — logo as base64) |
| POST | `/api/links/bulk` | ✓ | Bulk operations (`{action: "delete"\|"tag"\|"expire", codes: […]}`) |
| GET | `/api/links/export` | ✓ | Download all links as CSV |
| POST | `/api/links/import` | ✓ | Import links from CSV text (`{csv: "…"}`) |
| GET | `/api/health` | — | Health check (`{"status":"ok"}`) |
| GET | `/:code` | — | Redirect to destination URL |

### Admin

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/admin/users` | Admin | List all users with link counts |
| POST | `/api/admin/users` | Admin | Create user (`{username, password, is_admin}`) |
| DELETE | `/api/admin/users/:id` | Admin | Delete user (cannot delete self) |
| PATCH | `/api/admin/users/:id/password` | Admin | Change user password (`{password}`) |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:5000` | Public URL of your instance — used in short links and QR codes |
| `APP_NAME` | `to.ALWISP` | Display name shown in the header, hero, login modal, and page title. Names with a dot (e.g. `go.mysite.io`) are split and styled automatically; names without a dot render as plain text. |
| `PORT` | `5000` | Port Gunicorn listens on |
| `DEBUG` | `false` | Flask debug mode (keep false in production) |
| `SECRET_KEY` | *(none — required)* | Signs session cookies — use a long random string |
| `ADMIN_PASSWORD` | *(none — required)* | Password for the admin account — upserted on every startup |
| `ADMIN_USERNAME` | `admin` | Username for the admin account |
| `DB_PATH` | `/app/data/sniplink.db` | SQLite file location (inside Docker volume) |
| `COOKIE_SECURE` | `false` | Set `true` only if Flask receives HTTPS directly (not behind a proxy) |

---

## 🔄 Updating

Your data lives in the Docker volume and is preserved across updates.

```bash
docker build -t sniplink:latest .
docker stop sniplink && docker rm sniplink
docker run -d --name sniplink --restart unless-stopped \
  -p 5000:5000 -v sniplink-data:/app/data \
  -e BASE_URL=https://yourdomain.com \
  -e APP_NAME=to.ALWISP \
  -e SECRET_KEY=your-secret \
  -e ADMIN_PASSWORD=your-password \
  sniplink:latest
```

On Unraid, click **Force Update** on the container in the Docker tab.

> Sessions survive container restarts as long as `SECRET_KEY` stays the same. If you change `SECRET_KEY`, the browser session cookie will be invalid and you'll need to log in again — this is expected.
