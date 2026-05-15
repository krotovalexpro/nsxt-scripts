# NSX-T Traffic Monitor

A web-based tool for collecting and visualizing traffic statistics from **VMware NSX-T Tier-1 (T1) routers**. Measures throughput (RX/TX) per T1 router with byte, packet, and drop counters over a user-defined time interval.

> 🌐 **Web UI** (FastAPI) — select an NSX Manager, set the interval, and get an HTML report.
> ⌨️ **CLI** (`nsx-monitor.py`) — snapshot, delta-report, or interval-based monitoring from the terminal.

---

## Features

- **Multi-NSX support** — save multiple NSX Manager connections and switch between them
- **Configurable interval** — measure traffic over 1–60 minutes
- **T1 filtering** — collect stats for specific T1 routers by name/ID (case-insensitive partial match)
- **Parallel collection** — multi-threaded (8 workers) for fast polling of 400+ T1 routers
- **Anti-rate-limit** — safe concurrency to avoid NSX API 429 errors
- **Sortable HTML report** — click any column header to sort; color-coded traffic levels
- **Summary cards** — top TX, total RX/TX, success/error counts at a glance
- **Security** — passwords stored in memory only (never written to disk); read-only auditor accounts recommended
- **CLI mode** — headless operation with `--snapshot`, `--report`, and `--minutes` flags

---

## Quick Start (Docker)

**1. Clone the repo**

```bash
git clone https://github.com/krotovalexpro/nsxt-scripts.git
cd nsx-monitor
```

**2. Start the container**

```bash
docker compose up -d
```

**3. Open the web UI**

```
http://<server-ip>:80
```

> Port mapping is configured in `docker-compose.yml`. To change the host port (e.g., if port 80 is already in use), edit the `ports` section:
> ```yaml
> ports:
>   - "8080:80"   # host:8080 → container:80
> ```

**4. Add an NSX Manager connection and run a report**

---

## Manual Setup (without Docker)

**1. Install dependencies**

```bash
pip install -r requirements.txt
```

**2. Create a `config.yaml`**

```yaml
nsx_url: "https://nsx-manager.corp.local"
username: "monitor-user"
password: "your-password"
timeout: 300
```

**3. Run the CLI tool**

```bash
# One-shot snapshot → wait → report (5 min interval)
python nsx-monitor.py --minutes 5 --config config.yaml --output report.html

# Or two-phase: snapshot first
python nsx-monitor.py --snapshot --config config.yaml

# Then later, compare and generate a delta report
python nsx-monitor.py --report --snapshot-file snapshot_20250101_120000.json \
  --config config.yaml --output report.html
```

**4. Or start the Web UI**

```bash
python app.py
# → http://localhost:80
```

---

## CLI Usage

```
usage: nsx-monitor.py [-h] [--snapshot] [--report] [--minutes MINUTES]
                      [--output OUTPUT] [--config CONFIG] [--t1-name NAME]
                      [--workers N] [--debug]

Modes (use exactly one):
  --snapshot            Take a snapshot of current T1 counters
  --report              Compare against a saved snapshot and generate HTML report
  --minutes MINUTES, -m MINUTES
                        Monitor over N minutes (snapshot → wait → report)

Options:
  --output OUTPUT, -o OUTPUT
                        Path to output HTML report (default: <pwd>/report.html)
  --config CONFIG       Path to config.yaml (default: next to the script)
  --t1-name NAME        Filter: collect stats only for matching T1 (partial match)
  --workers N           Parallel worker threads (default: 8)
  --debug               Enable debug logging
```

### Examples

```bash
# Monitor all T1 routers for 10 minutes
python nsx-monitor.py -m 10 -c config.yaml -o report.html

# Monitor with a specific T1 filter
python nsx-monitor.py -m 5 --t1-name client-42 -c config.yaml

# Take a snapshot only (no report yet)
python nsx-monitor.py --snapshot -c config.yaml

# Generate report from existing snapshot
python nsx-monitor.py --report --snapshot-file snapshot_123.json -c config.yaml -o report.html

# Use fewer workers on a loaded NSX
python nsx-monitor.py -m 5 --workers 4 -c config.yaml
```

---

## Web UI Usage

1. **Add NSX Manager** — select *"➕ Add new NSX…"* from the dropdown, fill in name, URL, login, and password. Click **➕ Add**.
2. **Configure report** — select the NSX Manager, set the **Interval (min)**, optionally enter a **T1 name filter**, and provide a **password** if not saved.
3. **Run** — click **▶ Run**.
4. **View report** — when collection completes, click **📊 Open report** to see the results.

> 🛡️ **Security:** Passwords are stored in memory only, never persisted to disk. Saved connections store only name, URL, and username.

---

## Report Columns

| Column | Unit | Description |
|--------|------|-------------|
| # | — | Rank (descending by TX Mbps) |
| T1 Name | — | Display name of the T1 router |
| ID | — | First 12 chars of the T1 UUID |
| RX MB/s | MB/s | Receive speed (megabytes per second) |
| TX MB/s | MB/s | Transmit speed (megabytes per second) |
| RX Mbps | Mbps | Receive speed (megabits per second) |
| TX Mbps | Mbps | Transmit speed (megabits per second) |
| RX pkt/s | pkt/s | Receive packets per second |
| TX pkt/s | pkt/s | Transmit packets per second |
| RX GB | GB | Total received data over interval |
| TX GB | GB | Total transmitted data over interval |
| Interval | s | Actual time between measurements |

> 🎨 **Color coding:** RX/TX Mbps values are highlighted:
> - Normal: `< 100 Mbps`
> - **Orange:** `100–1000 Mbps` (high load)
> - **Red bold:** `> 1000 Mbps` (critical load)

---

## How It Works

```
User → Web UI (FastAPI) → nsx-monitor.py (CLI)
                                   ↓
                            NSX Manager API
                                   ↓
                           T1 statistics collection
                                   ↓
                        ThreadPoolExecutor (8 workers)
                                   ↓
                    Snapshot #1 → Wait N min → Snapshot #2
                                   ↓
                           Delta computation
                                   ↓
                             HTML Report
```

The tool takes two snapshots of T1 router counters at a configurable interval, computes deltas (differences), and generates an HTML report with sortable columns and summary statistics. Parallel collection via `ThreadPoolExecutor` keeps collection time under ~60 seconds even for 400+ T1 routers, while limiting concurrency to avoid NSX API rate limiting (HTTP 429).

---

## Requirements

- **NSX-T version:** 3.x and above
- **NSX user permissions:** Auditor (read-only) or higher
- **Network:** HTTP/HTTPS access from the monitor server to NSX Manager
- **Python:** 3.10+
- **Docker** (optional, for containerized deployment)

### Python Dependencies

```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
jinja2>=3.1.0
pyyaml>=6.0
requests>=2.28.0
python-multipart>=0.0.5
```

---

## Project Structure

```
nsx-monitor/
├── app.py              # FastAPI web application
├── nsx-monitor.py      # CLI monitoring tool
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker Compose configuration
├── templates/
│   └── index.html      # Web UI frontend (dark theme)
├── data/               # Persistent data (created at runtime)
│   ├── nsx_connections.json  # Saved connections (no passwords)
│   └── reports/              # Generated HTML reports
└── CONFLUENCE_DOCS.md  # Full user documentation (Russian)
```

---

## FAQ

**Q: Empty report / all T1s in error?**  
Check NSX Manager URL, credentials, and network connectivity. The user needs at least Auditor permissions.

**Q: Many skipped T1s?**  
Normal. T1 routers without a T0 interface (e.g., isolated VRFs) have no traffic statistics and are skipped.

**Q: Can I run multiple reports simultaneously?**  
Yes, but not recommended more than 3 concurrent reports per session — each consumes worker threads.

**Q: Password asked every time?**  
Yes. Passwords are intentionally not persisted to disk for security. On page reload or service restart, you'll need to re-enter the password.

**Q: How to measure traffic over an hour?**  
Set interval to 60 minutes. The report will be ready in ~60 minutes.

**Q: Self-signed certificates?**  
Supported — certificate verification is disabled internally.

---

## License

MIT
