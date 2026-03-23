# HoneyScan

HoneyScan is a web-based client honeypot and web threat detection platform for analyzing suspicious URLs, monitoring website behavior, and reviewing security signals through an interactive dashboard.

## Overview

HoneyScan combines a React frontend, an Express backend, MongoDB, Redis, and a sandbox-style scanning pipeline to inspect potentially unsafe URLs. It is designed to support security analysis workflows with scan history, risk scoring, and live progress updates.

## Features

- Submit URLs for security analysis
- View scan progress in real time
- Track suspicious behavior and threat indicators
- Review scan history and analysis results in a dashboard
- Store scan data in MongoDB
- Run the full stack with Docker Compose

## Tech Stack

- Frontend: React, Vite, SCSS, Socket.IO Client, Recharts
- Backend: Node.js, Express, Socket.IO, Bull, Mongoose
- Data Stores: MongoDB, Redis
- Infrastructure: Docker, Docker Compose
- Scanning and analysis: Puppeteer, Suricata, Wireshark/tshark, VirtualBox support

## Project Structure

```text
honeyscan/
|- client/      Frontend application
|- server/      Backend API and scanning services
|- scripts/     Startup scripts
|- docker-compose.yml
|- .env.example
`- README.md
```

## Prerequisites

Before running the project locally, make sure you have:

- Node.js 18 or newer
- npm
- MongoDB
- Redis
- Docker and Docker Compose for containerized setup

Optional for advanced sandbox analysis:

- VirtualBox
- Wireshark or tshark
- Suricata

## Environment Setup

1. Copy the example environment file.
2. Update the values for your local machine.

```bash
cp .env.example .env
```

Important variables include:

- `PORT`
- `MONGO_URI`
- `REDIS_URL`
- `JWT_SECRET`
- `CLIENT_URL`
- `SKIP_VM`
- `SKIP_WIRESHARK`
- `SKIP_SURICATA`

For local development, the example file already enables the skip flags so the project can run without the full sandbox stack.

## 🚀 Quick Start (Docker - Recommended)

```bash
cp .env.example .env
docker-compose up --build -d
```

**Demo Data (optional):**
```bash
docker-compose exec server node /app/services/seedDemo.js
```

Optional JSON seed files can also be placed in `server/data/*.json`. Running the same
`seedDemo.js` command will import those files into MongoDB after the generated demo scans.

**Access:**
- ✨ Dashboard: http://localhost:3000
- 🔧 Server API: http://localhost:5000/health

**Stop:**
```bash
docker-compose down -v  # -v clears volumes
```

## Features Now Fully Functional

✅ **Live URL Scanning** (Puppeteer + signals)
✅ **Realtime Progress** (Socket.IO terminal)
✅ **Risk Scoring** (weighted ML model)
✅ **Charts & History** (Recharts + MongoDB)
✅ **IoC Extraction** (domains/IPs/hashes)
✅ **Fallback Mode** (no VBox/tshark needed)
✅ **Settings Page** (theme, weights, prefs)

## Run Locally Without Docker

### Backend

```bash
cd server
npm install
npm run dev
```

### Frontend

```bash
cd client
npm install
npm run dev
```

## Available Scripts

Root:

```bash
npm start
```

Client:

```bash
npm run dev
npm run build
npm run preview
```

Server:

```bash
npm run dev
npm start
```

## API Areas

The backend includes routes for:

- Authentication
- Scan submission and results
- Threat scoring
- Statistics and dashboard data
- IOC-related lookups

## Notes

- Development mode can skip VirtualBox, Wireshark, and Suricata using environment flags.
- Docker is useful for the application stack, while some sandbox capabilities may still depend on host-level security tools.
- Do not scan systems or URLs without authorization.
