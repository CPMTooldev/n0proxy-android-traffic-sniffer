#!/usr/bin/env python3
"""Local web dashboard for read-only Frida TCP/UDP socket monitoring."""
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import http.server
import json
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

try:
    import frida
except ImportError:
    frida = None

ROOT = Path(__file__).resolve().parent
AGENT_PATH = ROOT / "agent.js"
UI_PATH = ROOT / "web" / "index.html"


class State:
    def __init__(self, remote: str, max_events: int = 5000):
        self.remote = remote
        self.lock = threading.RLock()
        self.events: collections.deque[dict[str, Any]] = collections.deque(maxlen=max_events)
        self.next_id = 1
        self.device = None
        self.session = None
        self.script = None
        self.target: dict[str, Any] | None = None
        self.agent_ready = False
        self.agent_hooks = 0
        self.last_error: str | None = None
        self.started_at: float | None = None
        self.counters = {"TCP": 0, "UDP": 0, "IN": 0, "OUT": 0, "bytes": 0}
        self.last_app_scan: dict[str, Any] = {
            "applications_seen": 0,
            "running_applications": 0,
            "processes_seen": 0,
            "errors": [],
        }

    def _load_device(self):
        if frida is None:
            raise RuntimeError("Python Frida bindings are missing. Install the frida package matching frida-server.")
        if self.device is None:
            manager = frida.get_device_manager()
            self.device = manager.add_remote_device(self.remote)
        return self.device

    def applications(self):
        device = self._load_device()
        found: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        app_ids: set[str] = set()
        applications_seen = 0
        processes_seen = 0

        try:
            apps = device.enumerate_applications()
            applications_seen = len(apps)
            for app in apps:
                pid = int(getattr(app, "pid", 0) or 0)
                identifier = str(getattr(app, "identifier", "") or "")
                if not identifier:
                    continue
                app_ids.add(identifier)
                if pid > 0:
                    found[identifier] = {
                        "identifier": identifier,
                        "name": str(getattr(app, "name", "") or identifier),
                        "pid": pid,
                    }
        except Exception as exc:
            errors.append(f"enumerate_applications: {type(exc).__name__}: {exc}")

        # Include processes that Frida does not expose as application records.
        try:
            processes = device.enumerate_processes()
            for proc in processes:
                pid = int(getattr(proc, "pid", 0) or 0)
                name = str(getattr(proc, "name", "") or "")
                if pid <= 0 or not name:
                    continue
                processes_seen += 1
                params = getattr(proc, "parameters", {}) or {}
                identifier = str(params.get("identifier") or "") if isinstance(params, dict) else ""
                if not identifier:
                    # Android secondary processes commonly use package:process.
                    identifier = next(
                        (app_id for app_id in app_ids if name == app_id or name.startswith(app_id + ":")),
                        name,
                    )
                found.setdefault(identifier, {
                    "identifier": identifier,
                    "name": name,
                    "pid": pid,
                })
        except Exception as exc:
            errors.append(f"enumerate_processes: {type(exc).__name__}: {exc}")

        with self.lock:
            self.last_app_scan = {
                "applications_seen": applications_seen,
                "running_applications": sum(
                    1 for app in found.values() if app["identifier"] in app_ids
                ),
                "processes_seen": processes_seen,
                "errors": errors,
            }
        return sorted(found.values(), key=lambda x: (x["name"].lower(), x["identifier"]))

    def _append(self, item: dict[str, Any]):
        with self.lock:
            item["id"] = self.next_id
            self.next_id += 1
            item.setdefault("time", dt.datetime.now().astimezone().isoformat(timespec="milliseconds"))
            self.events.append(item)
            protocol = item.get("protocol")
            direction = item.get("direction")
            if protocol in ("TCP", "UDP"):
                self.counters[protocol] += 1
            if direction in ("IN", "OUT"):
                self.counters[direction] += 1
            if isinstance(item.get("size"), int):
                self.counters["bytes"] += item["size"]

    def on_message(self, message, data):
        mtype = message.get("type")
        if mtype == "error":
            desc = message.get("description") or message.get("stack") or str(message)
            with self.lock:
                self.last_error = str(desc)
            self._append({"kind": "error", "message": str(desc)[:3000]})
            return
        payload = message.get("payload") or {}
        if not isinstance(payload, dict):
            self._append({"kind": "agent", "message": str(payload)[:1000]})
            return
        kind = payload.get("kind")
        if kind == "ready":
            with self.lock:
                self.agent_ready = True
                self.agent_hooks = int(payload.get("hooks", 0))
            self._append({"kind": "status", "message": f"Agent ready, {self.agent_hooks} hooks installed"})
        elif kind == "agent_error":
            err = f"{payload.get('where')}: {payload.get('error')}"
            with self.lock:
                self.last_error = err
            self._append({"kind": "error", "message": err})
        elif kind == "network":
            raw = bytes(data) if data else b""
            text_preview = raw[:512].decode("utf-8", errors="replace")
            clean = "".join(ch if ch in "\n\r\t" or ord(ch) >= 32 else "·" for ch in text_preview)
            self._append({
                "kind": "network",
                "direction": payload.get("direction", "?"),
                "protocol": payload.get("protocol", "?"),
                "fd": payload.get("fd"),
                "remote": payload.get("remote", "unknown"),
                "size": int(payload.get("size", len(raw)) or 0),
                "captured": len(raw),
                "truncated": bool(payload.get("truncated")),
                "hex": raw[:4096].hex(" "),
                "ascii": clean,
                "base64": base64.b64encode(raw[:4096]).decode("ascii"),
            })
        elif kind == "connection":
            self._append({"kind": "connection", "fd": payload.get("fd"), "remote": payload.get("remote"), "result": payload.get("result")})
        else:
            self._append({"kind": "agent", "message": json.dumps(payload, ensure_ascii=False)[:1500]})

    def attach(self, identifier: str):
        if not identifier:
            raise ValueError("Choose an application first.")
        self.detach()
        self.clear()
        device = self._load_device()
        matches = [a for a in self.applications() if a["identifier"] == identifier]
        if not matches:
            raise RuntimeError(f"No running process found for {identifier}. Launch the app first, then refresh the app list.")
        app = matches[0]
        session = device.attach(app["pid"])
        script = session.create_script(AGENT_PATH.read_text(encoding="utf-8"), name="tcp-udp-web-interceptor")
        script.on("message", self.on_message)
        session.on("detached", self._on_detached)
        with self.lock:
            self.session = session
            self.script = script
            self.target = app
            self.agent_ready = False
            self.agent_hooks = 0
            self.last_error = None
            self.started_at = time.time()
            self.counters = {"TCP": 0, "UDP": 0, "IN": 0, "OUT": 0, "bytes": 0}
        try:
            script.load()
        except Exception:
            # Avoid leaving a half-attached session behind when agent load fails.
            with self.lock:
                self.script = None
                self.session = None
                self.target = None
                self.agent_ready = False
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
            raise
        self._append({"kind": "status", "message": f"Attached to {app['name']} ({app['pid']})"})
        return app

    def _on_detached(self, reason, crash):
        with self.lock:
            self.session = None
            self.script = None
            self.agent_ready = False
            if reason:
                self.last_error = f"Frida session detached: {reason}"
        self._append({"kind": "error" if crash else "status", "message": f"Frida session detached: {reason or 'unknown'}"})

    def detach(self):
        with self.lock:
            script, session = self.script, self.session
            self.script = None
            self.session = None
            self.agent_ready = False
            self.target = None
        if script:
            try:
                script.unload()
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass

    def status(self):
        with self.lock:
            return {
                "remote": self.remote,
                "attached": self.session is not None,
                "target": self.target,
                "agent_ready": self.agent_ready,
                "agent_hooks": self.agent_hooks,
                "last_error": self.last_error,
                "counters": dict(self.counters),
                "event_count": len(self.events),
                "app_scan": dict(self.last_app_scan),
            }

    def get_events(self, after: int):
        with self.lock:
            return [dict(e) for e in self.events if e.get("id", 0) > after]

    def clear(self):
        with self.lock:
            self.events.clear()
            self.counters = {"TCP": 0, "UDP": 0, "IN": 0, "OUT": 0, "bytes": 0}


PAGE = UI_PATH.read_text(encoding="utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FridaNetUI/1.0"

    def log_message(self, fmt, *args):
        print("[web] " + (fmt % args))

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def _authorized(self) -> bool:
        password = self.server.password  # type: ignore[attr-defined]
        if not password:
            return True
        expected = "Basic " + base64.b64encode(("frida:" + password).encode()).decode()
        supplied = self.headers.get("Authorization", "")
        return secrets.compare_digest(supplied, expected)

    def _json(self, status: int, payload: Any):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        if self._authorized():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Frida Network Dashboard"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/status":
            self._json(200, self.state.status())
        elif parsed.path == "/api/apps":
            try:
                apps = self.state.applications()
                with self.state.lock:
                    diagnostics = dict(self.state.last_app_scan)
                self._json(200, {"apps": apps, "diagnostics": diagnostics})
            except Exception as exc:
                self._json(502, {"error": str(exc)})
        elif parsed.path == "/api/events":
            query = urllib.parse.parse_qs(parsed.query)
            try:
                after = int(query.get("after", ["0"])[0])
            except ValueError:
                after = 0
            self._json(200, {"events": self.state.get_events(after)})
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        length = min(int(self.headers.get("Content-Length", "0") or 0), 100_000)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json(400, {"error": "Invalid JSON"})
            return
        try:
            if parsed.path == "/api/attach":
                app = self.state.attach(str(body.get("identifier", "")))
                self._json(200, {"ok": True, "target": app})
            elif parsed.path == "/api/detach":
                self.state.detach()
                self._json(200, {"ok": True})
            elif parsed.path == "/api/clear":
                self.state.clear()
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "Not found"})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, state, password):
        super().__init__(address, Handler)
        self.state = state
        self.password = password


def main():
    parser = argparse.ArgumentParser(description="Web dashboard for read-only Frida TCP/UDP socket monitoring")
    parser.add_argument("--remote", default="127.0.0.1:27042", help="Frida remote endpoint (default: 127.0.0.1:27042)")
    parser.add_argument("--host", default="127.0.0.1", help="Web bind address; use 0.0.0.0 for LAN access")
    parser.add_argument("--port", type=int, default=8765, help="Web port (default: 8765)")
    parser.add_argument("--password", default=None, help="Dashboard password; required automatically for LAN binding if omitted")
    args = parser.parse_args()

    password = args.password
    if args.host not in ("127.0.0.1", "localhost", "::1") and not password:
        password = secrets.token_urlsafe(12)
        print("\nLAN dashboard password (username: frida): " + password + "\n")

    state = State(args.remote)
    server = Server((args.host, args.port), state, password)
    print(f"Frida remote: {args.remote}")
    print(f"Dashboard: http://{args.host}:{args.port}/")
    if password:
        print("Dashboard login username: frida")
    print("Open the dashboard, refresh the app list, then attach to a running app.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        state.detach()
        server.server_close()


if __name__ == "__main__":
    main()
