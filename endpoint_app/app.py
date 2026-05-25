"""
SOC Endpoint Agent — Desktop GUI App

Standalone tkinter app that wraps the endpoint agent.
Users just fill in Server URL + Auth Token and hit Start.
Config is saved locally so it persists between runs.

Build into .exe:
    python build_endpoint_app.py
"""
from __future__ import annotations

import json
import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ── Config persistence ────────────────────────────────────────────────────────

CONFIG_FILE = Path.home() / ".soc_agent_config.json"

DEFAULT_CONFIG = {
    "server_url": "",
    "auth_token": "",
    "poll_interval": 5,
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ── Agent runner (runs in background thread) ──────────────────────────────────

AGENT_ID_FILE = Path.home() / ".soc_agent_id"


def _get_or_create_agent_id() -> str:
    if AGENT_ID_FILE.exists():
        return AGENT_ID_FILE.read_text().strip()
    new_id = f"agent-{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    AGENT_ID_FILE.write_text(new_id)
    return new_id


def run_agent(server_url: str, auth_token: str, poll_interval: int,
              log_q: queue.Queue, stop_event: threading.Event):
    """
    Agent loop that runs in a background thread.
    Sends log messages to log_q for the GUI to display.
    """
    import httpx

    # Patch settings so all imported modules use our config
    os.environ["CENTRAL_SERVER_URL"] = server_url
    os.environ["AGENT_AUTH_TOKEN"] = auth_token
    os.environ["AGENT_POLL_INTERVAL"] = str(poll_interval)

    # Re-import settings so the patched env is picked up
    # (Settings is a class instance, we need to refresh it)
    try:
        from shared import config as _cfg_mod
        _cfg_mod.settings.CENTRAL_SERVER_URL = server_url
        _cfg_mod.settings.AGENT_AUTH_TOKEN = auth_token
        _cfg_mod.settings.AGENT_POLL_INTERVAL = poll_interval
    except Exception:
        pass

    def log(msg: str):
        ts = time.strftime("%H:%M:%S")
        log_q.put(f"[{ts}] {msg}")

    headers = {"Authorization": f"Bearer {auth_token}"}
    agent_id = _get_or_create_agent_id()
    hostname = socket.gethostname()

    log(f"Agent ID : {agent_id}")
    log(f"Hostname : {hostname}")
    log(f"Server   : {server_url}")
    log(f"Platform : {platform.system()} {platform.release()}")
    log("─" * 50)

    # Capabilities
    try:
        from endpoint_agent.modules import available_actions
        caps = available_actions()
    except Exception as e:
        caps = []
        log(f"[WARN] Could not load modules: {e}")

    reg_payload = {
        "agent_id": agent_id,
        "hostname": hostname,
        "os": platform.system(),
        "os_version": platform.version(),
        "agent_version": "0.1.0",
        "capabilities": caps,
    }

    with httpx.Client(verify=False) as client:
        # Register
        registered = False
        while not stop_event.is_set() and not registered:
            try:
                r = client.post(f"{server_url}/agents/register",
                                json=reg_payload, headers=headers, timeout=10)
                if r.status_code == 200:
                    log(f"✓ Registered with server")
                    registered = True
                else:
                    log(f"✗ Registration failed: HTTP {r.status_code} — retrying in 10s")
                    stop_event.wait(10)
            except Exception as e:
                log(f"✗ Cannot reach server: {e} — retrying in 10s")
                stop_event.wait(10)

        if not registered:
            log_q.put("__STOPPED__")
            return

        log("Polling for jobs...")

        # Main loop
        while not stop_event.is_set():
            try:
                # Heartbeat
                client.post(f"{server_url}/agents/heartbeat",
                            json={"agent_id": agent_id},
                            headers=headers, timeout=10)

                # Poll for job
                r = client.get(f"{server_url}/agents/{agent_id}/next-job",
                               headers=headers, timeout=10)
                if r.status_code == 200:
                    job = r.json().get("job")
                    if job:
                        job_id = job["job_id"]
                        actions = job.get("actions", [])
                        log(f"► Job {job_id} ({len(actions)} action(s))")

                        from endpoint_agent.modules import REGISTRY
                        from shared.schemas import JobResult, ActionResult
                        results = []
                        for action in actions:
                            name = action["name"]
                            params = action.get("params", {}) or {}
                            handler = REGISTRY.get(name)
                            if not handler:
                                results.append(ActionResult(
                                    action=name, success=False,
                                    duration_seconds=0.0,
                                    error=f"No handler for '{name}'"))
                                log(f"  ✗ {name}: no handler")
                                continue
                            t0 = time.time()
                            try:
                                data = handler(params)
                                dur = round(time.time() - t0, 2)
                                results.append(ActionResult(
                                    action=name, success=True,
                                    duration_seconds=dur, data=data))
                                log(f"  ✓ {name} ({dur}s)")
                            except Exception as e:
                                dur = round(time.time() - t0, 2)
                                results.append(ActionResult(
                                    action=name, success=False,
                                    duration_seconds=dur, error=str(e)))
                                log(f"  ✗ {name}: {e}")

                        result = JobResult(job_id=job_id, agent_id=agent_id, results=results)
                        client.post(f"{server_url}/jobs/{job_id}/result",
                                    json=result.model_dump(mode="json"),
                                    headers=headers, timeout=30)
                        log(f"✓ Job {job_id} submitted")

            except Exception as e:
                log(f"[WARN] Loop error: {e}")

            stop_event.wait(poll_interval)

    log("Agent stopped.")
    log_q.put("__STOPPED__")


# ── GUI ───────────────────────────────────────────────────────────────────────

class AgentApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SOC Endpoint Agent")
        self.resizable(True, True)
        self.minsize(600, 480)
        self._cfg = load_config()
        self._stop_event: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._log_q: queue.Queue = queue.Queue()
        self._running = False
        self._build_ui()
        self._poll_log()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # Dark theme
        self.configure(bg="#0d1117")
        style = ttk.Style(self)
        style.theme_use("clam")
        for widget in ("TFrame", "TLabelframe", "TLabelframe.Label"):
            style.configure(widget, background="#0d1117", foreground="#c9d1d9")
        style.configure("TLabel", background="#0d1117", foreground="#c9d1d9")
        style.configure("TEntry", fieldbackground="#161b22", foreground="#c9d1d9",
                        insertcolor="#c9d1d9", bordercolor="#30363d")
        style.configure("TButton", background="#21262d", foreground="#c9d1d9",
                        bordercolor="#30363d", focusthickness=0)
        style.map("TButton", background=[("active", "#30363d")])
        style.configure("Start.TButton", background="#238636", foreground="#ffffff")
        style.map("Start.TButton", background=[("active", "#2ea043"), ("disabled", "#21262d")])
        style.configure("Stop.TButton", background="#da3633", foreground="#ffffff")
        style.map("Stop.TButton", background=[("active", "#f85149"), ("disabled", "#21262d")])

        # ── Header ──
        hdr = tk.Frame(self, bg="#161b22", pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  SOC Endpoint Agent",
                 font=("Segoe UI", 16, "bold"),
                 bg="#161b22", fg="#58a6ff").pack(side="left", padx=18)
        self._status_dot = tk.Label(hdr, text="●", font=("Segoe UI", 18),
                                    bg="#161b22", fg="#6e7681")
        self._status_dot.pack(side="right", padx=6)
        self._status_lbl = tk.Label(hdr, text="Stopped",
                                    font=("Segoe UI", 11),
                                    bg="#161b22", fg="#6e7681")
        self._status_lbl.pack(side="right", padx=4)

        # ── Config frame ──
        cfg_frame = ttk.LabelFrame(self, text=" Configuration ", padding=14)
        cfg_frame.pack(fill="x", padx=16, pady=(12, 6))

        tk.Label(cfg_frame, text="Server URL", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", pady=4)
        self._url_var = tk.StringVar(value=self._cfg.get("server_url", ""))
        url_entry = ttk.Entry(cfg_frame, textvariable=self._url_var, width=55)
        url_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=4)

        tk.Label(cfg_frame, text="Auth Token", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", pady=4)
        self._token_var = tk.StringVar(value=self._cfg.get("auth_token", ""))
        token_entry = ttk.Entry(cfg_frame, textvariable=self._token_var,
                                width=55, show="●")
        token_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)

        tk.Label(cfg_frame, text="Poll Interval (s)", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).grid(row=2, column=0, sticky="w", pady=4)
        self._poll_var = tk.StringVar(value=str(self._cfg.get("poll_interval", 5)))
        ttk.Entry(cfg_frame, textvariable=self._poll_var, width=8).grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=4)

        cfg_frame.columnconfigure(1, weight=1)

        # Toggle show/hide token
        self._show_token = False
        def _toggle_token():
            self._show_token = not self._show_token
            token_entry.config(show="" if self._show_token else "●")
            show_btn.config(text="Hide" if self._show_token else "Show")
        show_btn = ttk.Button(cfg_frame, text="Show", width=5, command=_toggle_token)
        show_btn.grid(row=1, column=2, padx=(6, 0))

        # ── Buttons ──
        btn_frame = tk.Frame(self, bg="#0d1117")
        btn_frame.pack(fill="x", padx=16, pady=6)
        self._start_btn = ttk.Button(btn_frame, text="▶  Start Agent",
                                     style="Start.TButton", command=self._start)
        self._start_btn.pack(side="left", padx=(0, 8), ipadx=10, ipady=4)
        self._stop_btn = ttk.Button(btn_frame, text="■  Stop Agent",
                                    style="Stop.TButton", command=self._stop,
                                    state="disabled")
        self._stop_btn.pack(side="left", ipadx=10, ipady=4)
        ttk.Button(btn_frame, text="Clear Log", command=self._clear_log).pack(
            side="right", ipadx=6, ipady=4)

        # Agent info chips
        info_frame = tk.Frame(self, bg="#0d1117")
        info_frame.pack(fill="x", padx=16, pady=(0, 6))
        agent_id = _get_or_create_agent_id()
        tk.Label(info_frame, text=f"ID: {agent_id}",
                 bg="#161b22", fg="#8b949e", font=("Consolas", 9),
                 padx=8, pady=3, relief="flat").pack(side="left", padx=(0, 6))
        tk.Label(info_frame, text=f"Host: {socket.gethostname()}",
                 bg="#161b22", fg="#8b949e", font=("Consolas", 9),
                 padx=8, pady=3).pack(side="left", padx=(0, 6))
        tk.Label(info_frame, text=f"OS: {platform.system()} {platform.release()}",
                 bg="#161b22", fg="#8b949e", font=("Consolas", 9),
                 padx=8, pady=3).pack(side="left")

        # ── Log area ──
        log_frame = ttk.LabelFrame(self, text=" Agent Log ", padding=4)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(4, 14))
        self._log_box = scrolledtext.ScrolledText(
            log_frame, bg="#0d1117", fg="#c9d1d9",
            font=("Consolas", 10), state="disabled",
            wrap="word", bd=0, relief="flat",
            insertbackground="#c9d1d9",
        )
        self._log_box.pack(fill="both", expand=True)
        self._log_box.tag_config("ok",   foreground="#3fb950")
        self._log_box.tag_config("err",  foreground="#f85149")
        self._log_box.tag_config("warn", foreground="#d29922")
        self._log_box.tag_config("info", foreground="#58a6ff")
        self._log_box.tag_config("dim",  foreground="#6e7681")

    def _append_log(self, msg: str):
        self._log_box.configure(state="normal")
        tag = "ok" if "✓" in msg else "err" if "✗" in msg else \
              "warn" if "WARN" in msg else "info" if "►" in msg else "dim"
        self._log_box.insert("end", msg + "\n", tag)
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _clear_log(self):
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")

    def _poll_log(self):
        while not self._log_q.empty():
            msg = self._log_q.get_nowait()
            if msg == "__STOPPED__":
                self._set_status(False)
            else:
                self._append_log(msg)
        self.after(200, self._poll_log)

    def _set_status(self, running: bool):
        self._running = running
        if running:
            self._status_dot.config(fg="#3fb950")
            self._status_lbl.config(fg="#3fb950", text="Running")
            self._start_btn.config(state="disabled")
            self._stop_btn.config(state="normal")
        else:
            self._status_dot.config(fg="#6e7681")
            self._status_lbl.config(fg="#6e7681", text="Stopped")
            self._start_btn.config(state="normal")
            self._stop_btn.config(state="disabled")

    def _start(self):
        url = self._url_var.get().strip().rstrip("/")
        token = self._token_var.get().strip()
        try:
            poll = int(self._poll_var.get())
        except ValueError:
            poll = 5

        if not url:
            messagebox.showerror("Missing config", "Please enter the Server URL.")
            return
        if not token:
            messagebox.showerror("Missing config", "Please enter the Auth Token.")
            return

        save_config({"server_url": url, "auth_token": token, "poll_interval": poll})

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=run_agent,
            args=(url, token, poll, self._log_q, self._stop_event),
            daemon=True,
        )
        self._thread.start()
        self._set_status(True)
        self._append_log(f"Starting agent → {url}")

    def _stop(self):
        if self._stop_event:
            self._stop_event.set()
        self._append_log("Stopping agent...")

    def _on_close(self):
        if self._running:
            if messagebox.askyesno("Quit", "Agent is running. Stop it and quit?"):
                self._stop()
                self.after(1500, self.destroy)
        else:
            self.destroy()


def main():
    app = AgentApp()
    app.mainloop()


if __name__ == "__main__":
    main()
