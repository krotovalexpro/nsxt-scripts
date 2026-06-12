#!/usr/bin/env python3
"""
NSX-T Traffic Monitor — Web UI (FastAPI + Docker)
=================================================
Select NSX Manager → run report → view HTML result in browser.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
TEMPLATES = HERE / "templates"
STATIC = HERE / "static"
CONNECTIONS_FILE = DATA_DIR / "nsx_connections.json"
MONITOR_SCRIPT = HERE / "nsx-monitor.py"
REPORTS_DIR = DATA_DIR / "reports"

DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Jinja2 template engine (standalone, avoid Starlette's unhashable-dict bug)
# ---------------------------------------------------------------------------
import jinja2
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES)),
    autoescape=True,
    cache_size=0,
)

def render_template(name: str, **context) -> str:
    return _jinja_env.get_template(name).render(**context)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="NSX-T Traffic Monitor")

def _render(name: str, **context) -> HTMLResponse:
    """Render a Jinja2 template with the standard request context."""
    return HTMLResponse(render_template(name, **context))

# ---------------------------------------------------------------------------
# NSX Connections storage
# ---------------------------------------------------------------------------

class NSXConnection(BaseModel):
    name: str
    url: str
    username: str
    password: str = ""


def load_connections() -> list[dict]:
    if CONNECTIONS_FILE.exists():
        with open(CONNECTIONS_FILE) as f:
            return json.load(f)
    return []


def save_connections(conns: list[dict]):
    # Strip passwords before saving to disk — keep only for the session
    to_save = []
    for c in conns:
        entry = {k: v for k, v in c.items() if k != "password"}
        to_save.append(entry)
    with open(CONNECTIONS_FILE, "w") as f:
        json.dump(to_save, f, indent=2)


CONNECTIONS: list[dict] = load_connections()

# ---------------------------------------------------------------------------
# Running tasks
# ---------------------------------------------------------------------------

class TaskState:
    """Holds state for a running or completed report task."""
    __slots__ = ("id", "nsx_name", "task_type", "status", "progress",
                 "report_path", "error", "created_at", "finished_at",
                 "edge_data")

    def __init__(self, task_id: str, nsx_name: str, task_type: str = "traffic"):
        self.id = task_id
        self.nsx_name = nsx_name
        self.task_type = task_type  # "traffic" or "edge_map"
        self.status = "starting"  # starting → collecting → waiting → done/error
        self.progress = ""
        self.report_path: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = time.time()
        self.finished_at: Optional[float] = None
        self.edge_data: Optional[list[dict]] = None  # for edge_map tasks


_tasks: dict[str, TaskState] = {}


def _run_monitor(task: TaskState, conn: dict, minutes: int, t1_name: str = ""):
    """Run nsx-monitor.py as a subprocess and track progress."""
    try:
        task.status = "collecting"
        task.progress = "Collecting initial snapshot…"

        # Write a temporary config.yaml
        tmp_dir = REPORTS_DIR / task.id
        tmp_dir.mkdir(exist_ok=True)
        config_path = tmp_dir / "config.yaml"
        with open(config_path, "w") as f:
            f.write(f'nsx_url: "{conn["url"]}"\n')
            f.write(f'username: "{conn["username"]}"\n')
            f.write(f'password: "{conn.get("password", "")}"\n')
            f.write(f"timeout: 300\n")

        report_path = tmp_dir / "report.html"
        snapshot_path = tmp_dir / "snapshot.json"

        # Extra CLI args for T1 filter
        t1_args = ["--t1-name", t1_name] if t1_name else []

        # Phase 1: snapshot
        task.progress = "Phase 1/2: Collecting current counters…"
        result = subprocess.run(
            [
                sys.executable, str(MONITOR_SCRIPT),
                "--snapshot",
                "--output", str(report_path),
                "--config", str(config_path),
                "--workers", "8",
            ] + t1_args,
            cwd=str(tmp_dir),
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Snapshot failed:\n{result.stderr}")

        # Parse output to find snapshot file path
        snap_file = None
        for line in result.stdout.split("\n"):
            if "Snapshot saved" in line or "snapshot_" in line:
                parts = line.strip().split("→")
                if len(parts) > 1:
                    snap_file = parts[-1].strip()
                elif "Snapshot saved:" in line:
                    snap_file = line.split("Snapshot saved:")[-1].strip()

        if not snap_file or not Path(snap_file).exists():
            # Fallback: find snapshot files in tmp_dir
            snaps = list(tmp_dir.glob("snapshot_*.json"))
            if snaps:
                snap_file = str(snaps[0])

        if not snap_file:
            raise RuntimeError("Could not find snapshot file in output")

        # Phase 2: wait
        task.status = "waiting"
        for remaining in range(minutes * 60, 0, -10):
            mins, secs = divmod(remaining, 60)
            task.progress = f"Phase 2/2: Waiting {mins}m {secs:02d}s…"
            time.sleep(min(10, remaining))

        # Phase 3: report
        task.progress = "Phase 3/3: Collecting final snapshot and generating report…"
        result = subprocess.run(
            [
                sys.executable, str(MONITOR_SCRIPT),
                "--report", "--snapshot-file", snap_file,
                "--output", str(report_path),
                "--config", str(config_path),
                "--workers", "8",
            ] + t1_args,
            cwd=str(tmp_dir),
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Report generation failed:\n{result.stderr}")

        if not report_path.exists():
            raise RuntimeError("Report file was not generated")

        task.report_path = str(report_path)
        task.status = "done"
        task.progress = "Report ready!"

    except Exception as exc:
        task.status = "error"
        task.error = str(exc)
        task.progress = f"Error: {exc}"
    finally:
        task.finished_at = time.time()


# ---------------------------------------------------------------------------
# Edge Map task
# ---------------------------------------------------------------------------

def _run_edge_map(task: TaskState, conn: dict):
    """Run nsx-monitor.py --edge-map as a subprocess and capture JSON data."""
    try:
        task.status = "collecting"
        task.progress = "Collecting edge placement data…"

        # Write a temporary config.yaml
        tmp_dir = REPORTS_DIR / task.id
        tmp_dir.mkdir(exist_ok=True)
        config_path = tmp_dir / "config.yaml"
        with open(config_path, "w") as f:
            f.write(f'nsx_url: "{conn["url"]}"\n')
            f.write(f'username: "{conn["username"]}"\n')
            f.write(f'password: "{conn.get("password", "")}"\n')
            f.write(f"timeout: 300\n")

        report_path = tmp_dir / "edge_report.html"

        # Run CLI to get JSON data
        task.progress = "Fetching T1 locale-services and HA status…"
        result = subprocess.run(
            [
                sys.executable, str(MONITOR_SCRIPT),
                "--edge-map",
                "--json",
                "--config", str(config_path),
                "--workers", "8",
            ],
            cwd=str(tmp_dir),
            capture_output=True, text=True, timeout=600,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown error"
            raise RuntimeError(f"Edge map failed: {error_msg}")

        # Parse JSON from stdout
        import json as _json
        data = _json.loads(result.stdout)
        task.edge_data = data.get("t1_list", [])

        # Generate HTML report
        task.progress = "Generating report…"
        result2 = subprocess.run(
            [
                sys.executable, str(MONITOR_SCRIPT),
                "--edge-map",
                "--output", str(report_path),
                "--config", str(config_path),
                "--workers", "8",
            ],
            cwd=str(tmp_dir),
            capture_output=True, text=True, timeout=600,
        )

        if result2.returncode != 0:
            raise RuntimeError(f"Report generation failed:\n{result2.stderr}")

        if report_path.exists():
            task.report_path = str(report_path)

        task.status = "done"
        task.progress = f"Collected {len(task.edge_data)} T1s"

    except Exception as exc:
        task.status = "error"
        task.error = str(exc)
        task.progress = f"Error: {exc}"
    finally:
        task.finished_at = time.time()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _render("index.html", request=request, connections=CONNECTIONS)


@app.post("/connections/add")
async def add_connection(
    name: str = Form(...),
    url: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
):
    conn = {"name": name, "url": url, "username": username, "password": password}
    # Replace if name exists
    for i, c in enumerate(CONNECTIONS):
        if c["name"] == name:
            CONNECTIONS[i] = conn
            save_connections(CONNECTIONS)
            return {"status": "updated", "name": name}
    CONNECTIONS.append(conn)
    save_connections(CONNECTIONS)
    return {"status": "added", "name": name}


@app.post("/connections/delete")
async def delete_connection(name: str = Form(...)):
    global CONNECTIONS
    CONNECTIONS = [c for c in CONNECTIONS if c["name"] != name]
    save_connections(CONNECTIONS)
    return {"status": "deleted", "name": name}


@app.post("/run")
async def run_report(
    nsx_name: str = Form(...),
    minutes: int = Form(5),
    t1_name: str = Form(""),
):
    # Find connection
    conn = next((c for c in CONNECTIONS if c["name"] == nsx_name), None)
    if not conn:
        raise HTTPException(404, f"NSX '{nsx_name}' not found")

    task_id = uuid.uuid4().hex[:12]
    task = TaskState(task_id, nsx_name)

    # If password is empty, try to find it from stored connections (JSON)
    # JSON doesn't store passwords for security, so prompt user
    if not conn.get("password"):
        return JSONResponse({
            "status": "need_password",
            "task_id": task_id,
            "nsx_name": nsx_name,
        })

    _tasks[task_id] = task

    # Launch in background thread
    thread = Thread(target=_run_monitor, args=(task, conn, minutes, t1_name), daemon=True)
    thread.start()

    return {"status": "started", "task_id": task_id, "nsx_name": nsx_name}


@app.post("/run-with-password")
async def run_report_with_password(
    nsx_name: str = Form(...),
    password: str = Form(...),
    minutes: int = Form(5),
    t1_name: str = Form(""),
):
    conn = next((c for c in CONNECTIONS if c["name"] == nsx_name), None)
    if not conn:
        # Allow running with a temporary connection
        conn = {
            "name": nsx_name,
            "url": nsx_name,  # fallback — name might be URL
            "username": "admin",
            "password": password,
        }
        # Try to find by url matching
        for c in CONNECTIONS:
            if c["url"] == nsx_name:
                conn = {**c, "password": password}
                break
        else:
            return JSONResponse({"status": "error", "error": f"NSX '{nsx_name}' not found"}, status_code=404)

    conn = {**conn, "password": password}
    task_id = uuid.uuid4().hex[:12]
    task = TaskState(task_id, conn["name"])
    _tasks[task_id] = task

    thread = Thread(target=_run_monitor, args=(task, conn, minutes, t1_name), daemon=True)
    thread.start()

    return {"status": "started", "task_id": task_id, "nsx_name": conn["name"]}


@app.get("/task/{task_id}")
async def task_status(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    result = {
        "id": task.id,
        "nsx_name": task.nsx_name,
        "task_type": task.task_type,
        "status": task.status,
        "progress": task.progress,
        "created_at": task.created_at,
        "finished_at": task.finished_at,
        "error": task.error,
        "report_ready": task.report_path is not None,
        "edge_ready": task.edge_data is not None,
    }
    return result


@app.get("/report/{task_id}")
async def get_report(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if not task.report_path or not Path(task.report_path).exists():
        raise HTTPException(404, "Report not ready yet")

    with open(task.report_path) as f:
        html = f.read()
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Edge Map endpoints
# ---------------------------------------------------------------------------

@app.post("/run-edge-map")
async def run_edge_map(
    nsx_name: str = Form(...),
    password: str = Form(""),
):
    conn = next((c for c in CONNECTIONS if c["name"] == nsx_name), None)
    if not conn:
        raise HTTPException(404, f"NSX '{nsx_name}' not found")

    conn = {**conn}
    if password:
        conn["password"] = password

    if not conn.get("password"):
        return JSONResponse({
            "status": "need_password",
            "nsx_name": nsx_name,
        })

    task_id = uuid.uuid4().hex[:12]
    task = TaskState(task_id, nsx_name, task_type="edge_map")
    _tasks[task_id] = task

    thread = Thread(target=_run_edge_map, args=(task, conn), daemon=True)
    thread.start()

    return {"status": "started", "task_id": task_id, "nsx_name": nsx_name}


@app.get("/edge-data/{task_id}")
async def get_edge_data(task_id: str):
    """Return edge placement data as JSON for inline table rendering."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != "done":
        raise HTTPException(400, "Data not ready yet")
    if task.edge_data is None:
        raise HTTPException(404, "No edge data available")

    return JSONResponse({
        "status": "ok",
        "total": len(task.edge_data),
        "t1_list": task.edge_data,
    })


@app.get("/edge-report/{task_id}")
async def get_edge_report(task_id: str):
    """Return the full HTML edge placement report."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if not task.report_path or not Path(task.report_path).exists():
        raise HTTPException(404, "Report not ready yet")

    with open(task.report_path) as f:
        html = f.read()
    return HTMLResponse(content=html)


@app.get("/tasks", response_class=JSONResponse)
async def list_tasks():
    return [
        {
            "id": t.id,
            "nsx_name": t.nsx_name,
            "status": t.status,
            "progress": t.progress,
            "created_at": t.created_at,
            "finished_at": t.finished_at,
        }
        for t in sorted(_tasks.values(), key=lambda x: x.created_at, reverse=True)[:20]
    ]


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
