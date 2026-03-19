# 🍯 HoneyScan — Client-Side Honeypot Threat Detection Platform

> A full-stack MERN cybersecurity platform for submitting suspicious URLs to a sandboxed Puppeteer/VirtualBox environment, scoring behavioral signals via a weighted risk model, and investigating results through a real-time React dashboard.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HoneyScan Stack                         │
├────────────────┬───────────────────────┬────────────────────────┤
│   React Frontend│    Express Backend     │   Sandbox Layer        │
│   Vite + SCSS  │    Node.js + JWT       │   Puppeteer + CDP      │
│   Recharts     │    Socket.IO           │   VirtualBox VM        │
│   Socket.IO    │    Bull + Redis        │   tshark/Wireshark     │
│   5 Pages      │    MongoDB/Mongoose    │   Suricata IDS         │
└────────────────┴───────────────────────┴────────────────────────┘
```

---

## Prerequisites

### Host OS: Ubuntu 22.04 LTS (recommended)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install MongoDB 7.0
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org
sudo systemctl start mongod && sudo systemctl enable mongod

# Install Redis
sudo apt install -y redis-server
sudo systemctl start redis && sudo systemctl enable redis

# Install VirtualBox
sudo apt install -y virtualbox virtualbox-ext-pack

# Install tshark/Wireshark
sudo apt install -y tshark
sudo usermod -aG wireshark $USER  # Allow non-root capture

# Install Suricata
sudo apt install -y suricata
sudo systemctl start suricata && sudo systemctl enable suricata
```

---

## VirtualBox Setup

### 1. Create the Sandbox VM

```bash
# Create VM (Ubuntu 22.04 minimal recommended)
VBoxManage createvm --name "HoneyScan-Sandbox" --ostype Ubuntu_64 --register
VBoxManage modifyvm "HoneyScan-Sandbox" --memory 2048 --cpus 2 --nic1 hostonly --hostonlyadapter1 vboxnet0

# Configure vboxnet0 host-only network
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# After installing Ubuntu in the VM, install Node.js and Puppeteer dependencies:
# sudo apt install -y chromium-browser nodejs npm
# npm install -g puppeteer
```

### 2. Take Clean Snapshot

```bash
# Power off the VM after clean installation
VBoxManage controlvm "HoneyScan-Sandbox" poweroff

# Take the clean state snapshot (used for reset after each scan)
VBoxManage snapshot "HoneyScan-Sandbox" take "CleanState" --description "Clean sandbox state for honeypot scans"
```

### 3. Verify

```bash
VBoxManage snapshot "HoneyScan-Sandbox" list
# Should show: Name: CleanState
```

---

## Suricata Configuration

```bash
# Configure Suricata to monitor the vboxnet0 interface
sudo nano /etc/suricata/suricata.yaml

# Change af-packet interface to vboxnet0:
# af-packet:
#   - interface: vboxnet0

# Download Emerging Threats Open ruleset
sudo suricata-update
sudo suricata-update add-source emerging-threats https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz
sudo suricata-update

# Restart Suricata
sudo systemctl restart suricata

# Verify EVE JSON logging
sudo tail -f /var/log/suricata/eve.json
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/honeyscan.git
cd honeyscan

# ── Backend ──
cd server
cp ../.env.example .env
# Edit .env with your configuration
nano .env

npm install
mkdir -p captures

# ── Frontend ──
cd ../client
npm install
```

---

## Running in Development

```bash
# Terminal 1: Start backend
cd server
SKIP_VM=true SKIP_WIRESHARK=true SKIP_SURICATA=true npm run dev

# Terminal 2: Start frontend
cd client
npm run dev

# Visit: http://localhost:3000
```

> **Development Mode**: Setting `SKIP_VM=true`, `SKIP_WIRESHARK=true`, and `SKIP_SURICATA=true` bypasses the VirtualBox/tshark/Suricata requirements so you can develop and test the UI with real Puppeteer scans only.

---

## Running in Production (Docker)

```bash
# Build and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f server
docker-compose logs -f client

# Stop
docker-compose down
```

> **Note**: For full sandbox functionality with Docker, the server container needs access to VBoxManage on the host. Set `extra_hosts: host.docker.internal:host-gateway` and map VBoxManage via volume or exec into the host.

---

## Running Without Docker (Recommended for Production)

```bash
# Start MongoDB and Redis (system services)
sudo systemctl start mongod redis suricata

# Backend
cd server
NODE_ENV=production npm start

# Frontend (build + serve via nginx)
cd client
npm run build
sudo cp -r dist/* /var/www/honeyscan/
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | Environment mode |
| `PORT` | `5000` | Server port |
| `MONGO_URI` | `mongodb://localhost:27017/honeyscan` | MongoDB connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | — | **Required.** Long random secret for JWT signing |
| `CLIENT_URL` | `http://localhost:3000` | Frontend URL (CORS) |
| `VBOX_VM_NAME` | `HoneyScan-Sandbox` | VirtualBox VM name |
| `VBOX_SNAPSHOT_NAME` | `CleanState` | Snapshot to restore before each scan |
| `VBOX_VM_IP` | `192.168.56.101` | VM IP on host-only network |
| `SKIP_VM` | `false` | Skip VirtualBox restore (dev mode) |
| `WIRESHARK_INTERFACE` | `vboxnet0` | Network interface for tshark capture |
| `CAPTURE_DIR` | `./captures` | Directory for .pcap files |
| `SKIP_WIRESHARK` | `false` | Skip packet capture (dev mode) |
| `SURICATA_EVE_LOG` | `/var/log/suricata/eve.json` | Suricata EVE JSON log path |
| `SKIP_SURICATA` | `false` | Skip Suricata checks (dev mode) |

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register new analyst account |
| POST | `/api/auth/login` | Login and receive JWT |
| GET  | `/api/auth/me` | Get current user |
| PUT  | `/api/auth/settings` | Update user settings |

### Scans
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scans` | Submit URL for scanning |
| GET  | `/api/scans` | List scans (paginated) |
| GET  | `/api/scans/recent` | Recent scans for live feed |
| GET  | `/api/scans/:id` | Full scan details |
| GET  | `/api/scans/:id/dom` | DOM snapshots |
| DELETE | `/api/scans/:id` | Delete scan |
| POST | `/api/scans/bulk-delete` | Bulk delete |
| GET  | `/api/scans/:id/export` | Export as JSON |
| POST | `/api/scans/export-csv` | Export as CSV |
| POST | `/api/scans/:id/ioc/:iocId/virustotal` | VirusTotal IoC lookup |

### Scoring & Stats
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/score` | Stateless risk scoring endpoint |
| GET  | `/api/stats/overview` | Dashboard stat cards |
| GET  | `/api/stats/scans-per-day` | Area chart data |
| GET  | `/api/stats/severity-distribution` | Donut chart data |
| GET  | `/api/stats/heatmap` | 7×24 heatmap data |

### Socket.IO Events
| Direction | Event | Payload |
|---|---|---|
| Client→Server | `subscribe` | `{ scanId }` |
| Client→Server | `unsubscribe` | `{ scanId }` |
| Server→Client | `scan:progress` | `{ level, message, timestamp }` |
| Server→Client | `scan:step` | `{ step, name, status }` |
| Server→Client | `scan:network` | `{ method, url, status, flagged }` |
| Server→Client | `scan:complete` | `{ scanId, threatScore, riskLevel, iocCount }` |
| Server→Client | `scan:error` | `{ error }` |

---

## Risk Scoring Model

```
ThreatScore = Σ(wᵢ × Iᵢ) × 100

Where Iᵢ = normalize(rawSignalᵢ) ∈ [0, 1]
```

| Signal | Default Weight | Normalization Cap |
|---|---|---|
| scriptCount | 25% | 50 scripts |
| redirectCount | 20% | 5 redirects |
| hiddenIframes | 20% | 3 iframes |
| downloadAttempts | 15% | 2 downloads |
| domMutationRate | 10% | 1.0 (mutations/sec) |
| externalScripts | 10% | 20 scripts |

| Score Range | Risk Level | Action |
|---|---|---|
| 0–25 | Safe | No action required |
| 26–50 | Medium | Manual review recommended |
| 51–75 | High | Block domain, escalate |
| 76–100 | Critical | Immediate incident response |

---

## Project Structure

```
honeyscan/
├── docker-compose.yml
├── .env.example
├── README.md
├── server/
│   ├── index.js              # Express + Socket.IO entry
│   ├── config/
│   │   ├── db.js             # MongoDB connection
│   │   └── redis.js          # Redis/Bull connection
│   ├── models/
│   │   ├── Scan.js           # Full scan schema with aggregations
│   │   └── User.js           # Auth + settings schema
│   ├── routes/
│   │   ├── auth.js           # JWT auth endpoints
│   │   ├── scans.js          # Scan CRUD + VT integration
│   │   ├── score.js          # Stateless risk scoring
│   │   ├── stats.js          # Dashboard aggregations
│   │   └── iocs.js           # IoC queries
│   ├── middleware/
│   │   └── auth.js           # JWT verification middleware
│   ├── services/
│   │   ├── scanQueue.js      # Bull queue setup + processor registration
│   │   ├── scanProcessor.js  # Full scan pipeline orchestrator
│   │   ├── riskScoringService.js  # Weighted scoring + IoC extraction
│   │   ├── wiresharkService.js    # tshark capture + parsing
│   │   ├── suricataService.js     # EVE JSON tail + alert filtering
│   │   └── virusTotalService.js   # VT v3 API integration
│   ├── sandbox/
│   │   ├── scan.js           # Puppeteer + full CDP instrumentation
│   │   └── vmManager.js      # VBoxManage snapshot restore
│   └── captures/             # .pcap file storage
└── client/
    ├── src/
    │   ├── context/          # Auth, Theme, Toast contexts
    │   ├── services/         # Axios API client + Socket.IO
    │   ├── components/
    │   │   ├── layout/       # AppLayout sidebar + mesh bg
    │   │   └── ui/           # Shared components + Toast
    │   ├── pages/
    │   │   ├── Dashboard/    # Stats, charts, heatmap, live feed
    │   │   ├── Scanner/      # URL input, stepper, terminal, network table
    │   │   ├── Analysis/     # Gauge, signals, IoC table, redirect chain
    │   │   ├── History/      # Paginated table, bulk ops, export
    │   │   ├── Settings/     # Theme, weights, VT key, defaults
    │   │   └── Auth/         # Login + Register
    │   └── styles/
    │       ├── globals.scss  # CSS variables for 3 themes
    │       └── animations.scss # All keyframe animations
    └── vite.config.js
```

---

## Security Notes

1. **JWT Secret**: Generate a cryptographically secure secret: `openssl rand -hex 64`
2. **Rate Limiting**: Scanner endpoint is limited to 5 scans/minute per IP
3. **Sandbox Isolation**: Each scan restores a clean VM snapshot to prevent cross-contamination
4. **Network Isolation**: The VM uses a host-only network (vboxnet0) — no internet access from VM
5. **PCAP Storage**: Capture files are stored locally; ensure `/captures` directory is not publicly accessible
6. **API Keys**: VirusTotal API keys are stored encrypted in MongoDB and never returned in API responses

---

## Troubleshooting

**VirtualBox restore fails:**
```bash
VBoxManage list vms              # Verify VM name
VBoxManage snapshot "HoneyScan-Sandbox" list  # Verify snapshot name
sudo usermod -aG vboxusers $USER  # Add user to vboxusers group
```

**tshark permission denied:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
sudo usermod -aG wireshark $USER
newgrp wireshark
```

**Suricata not logging alerts:**
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml  # Test config
sudo journalctl -u suricata -f                    # Live logs
cat /var/log/suricata/stats.log | tail -20        # Check stats
```

**Redis connection failed:**
```bash
redis-cli ping  # Should return PONG
sudo systemctl status redis
```

---

## Research Context

HoneyScan was developed as part of a research project on client-side honeypot frameworks for web threat detection at PES University, Department of Computer Applications. The platform implements the full detection pipeline described in the accompanying IEEE-format research paper, with behavioral signal extraction, weighted risk scoring, and real-time analyst tooling.

---

*HoneyScan — Built for responsible security research. Do not scan URLs you do not own or have permission to test.*
