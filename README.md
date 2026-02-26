# SnipLink — URL Shortener & QR Code Generator

A self-hosted URL shortener with QR code generation. Built on Python/Flask + SQLite. Runs as a Docker container — designed for Unraid but works anywhere Docker runs.

---

## 📍 Project Roadmap

### ✅ Phase 1 — Core MVP (Complete)
- [x] URL shortening with random or custom codes
- [x] Click tracking with timestamp, referrer, user-agent
- [x] QR code generation per short link (backend-rendered PNG)
- [x] Custom QR generator with color and size controls
- [x] Link expiration support
- [x] Dashboard with stats (total links, total clicks, avg clicks/link)
- [x] Link management (view, copy, delete)
- [x] Dark-mode frontend with polished UI
- [x] REST API
- [x] SQLite database (zero config, single file, Docker volume)
- [x] Docker image with multi-stage build
- [x] Unraid-ready container config

### 🔜 Phase 2 — Analytics & Management
- [ ] Click analytics chart (daily clicks over time, per-link)
- [ ] Referrer breakdown
- [ ] Device/browser breakdown from User-Agent parsing
- [ ] Link editing (change destination, update expiry)
- [ ] Bulk link import via CSV
- [ ] Search/filter links in dashboard
- [ ] Link tags/categories

### 🔜 Phase 3 — Auth & Multi-user
- [ ] User accounts (registration, login, JWT sessions)
- [ ] Per-user link ownership and dashboards
- [ ] API key management
- [ ] Role-based access (admin, member)
- [ ] Team workspaces

### 🔜 Phase 4 — Integrations & Power Features
- [ ] QR code with embedded logo/icon
- [ ] Custom domains per workspace
- [ ] Webhook on click events
- [ ] UTM parameter auto-append
- [ ] Browser extension integration

### 🔜 Phase 5 — Production Hardening
- [ ] Rate limiting per IP
- [ ] PostgreSQL/MySQL backend option
- [ ] Redis caching for hot links
- [ ] Admin dashboard

---

## 🐳 Docker Deployment

### Option A — Build locally

```bash
cd sniplink
docker build -t sniplink:latest .

docker run -d \
  --name sniplink \
  --restart unless-stopped \
  -p 5000:5000 \
  -v sniplink-data:/app/data \
  -e BASE_URL=http://to.alwisp.com \
  -e SECRET_KEY=replace-with-something-random \
  sniplink:latest
```

### Option B — Docker Compose

```bash
# Edit docker-compose.yml first — set BASE_URL and SECRET_KEY
docker compose up -d
```

---

## 🖥 Unraid Setup (Step-by-Step)

### Step 1 — Get the image onto Unraid

**Option 1: Build directly on Unraid**
Open the Unraid Terminal and run:
```bash
cd /mnt/user/appdata/sniplink-src
docker build -t sniplink:latest .
```

**Option 2: Push to Docker Hub (recommended)**
On any machine with Docker installed:
```bash
docker build -t yourdockerhubusername/sniplink:latest .
docker push yourdockerhubusername/sniplink:latest
```
Then use `yourdockerhubusername/sniplink:latest` as the repository in Unraid.

---

### Step 2 — Add container in Unraid UI

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

| Key | Value |
|---|---|
| `BASE_URL` | `http://to.alwisp.com` |
| `SECRET_KEY` | *(any long random string)* |
| `DEBUG` | `false` |

4. Click **Apply**

---

### Step 3 — Reverse proxy via Nginx Proxy Manager

If you're using Nginx Proxy Manager on Unraid (the most common setup):

1. **Proxy Hosts** → **Add Proxy Host**
2. Set:
   - Domain: `to.alwisp.com`
   - Forward Hostname/IP: your Unraid LAN IP (e.g. `192.168.1.100`)
   - Forward Port: `5000`
3. On the **SSL** tab — request a free Let's Encrypt certificate
4. Ensure your DNS A record for `to.alwisp.com` points to your public IP

Short links will then be served at `https://to.alwisp.com/abc123`.

---

### Step 4 — Verify

```bash
docker inspect --format='{{.State.Health.Status}}' sniplink
# Should return: healthy
```

---

## 🗂 Project Structure

```
sniplink/
├── app.py                # Flask backend
├── templates/
│   └── index.html        # Single-page frontend
├── static/               # Static assets
├── requirements.txt      # Python dependencies
├── Dockerfile            # Multi-stage Docker build
├── docker-compose.yml    # For non-Unraid deployments
├── .dockerignore
└── README.md
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/shorten` | Shorten a URL |
| GET | `/api/links` | List all links |
| GET | `/api/links/:code` | Link detail + click history |
| DELETE | `/api/links/:code` | Delete a link |
| GET | `/api/qr/:code` | QR PNG for a short link |
| GET | `/api/qr/custom` | QR for any arbitrary URL |
| GET | `/api/stats` | Aggregate stats |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:5000` | Public URL of your instance |
| `PORT` | `5000` | Port Gunicorn listens on |
| `DEBUG` | `false` | Flask debug mode |
| `SECRET_KEY` | `change-me-in-production` | Always change this in production |
| `DB_PATH` | `/app/data/sniplink.db` | SQLite file location (inside volume) |

---

## 🔄 Updating

After code changes, rebuild and redeploy — your data is safe in the volume:

```bash
docker build -t sniplink:latest .
docker stop sniplink && docker rm sniplink
docker run -d --name sniplink --restart unless-stopped \
  -p 5000:5000 -v sniplink-data:/app/data \
  -e BASE_URL=http://to.alwisp.com \
  -e SECRET_KEY=your-secret \
  sniplink:latest
```

In Unraid, just click **Force Update** on the container in the Docker tab.
