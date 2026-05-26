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
from tkinter import ttk, scrolledtext, messagebox, filedialog

# ── Config persistence ────────────────────────────────────────────────────────

CONFIG_FILE = Path.home() / ".soc_agent_config.json"

DEFAULT_CONFIG = {
    "server_url": "",
    "auth_token": "",
    "poll_interval": 5,
    "ghidra_path": "",
    "volatility_binary": "vol",
    "sample_binary": "",
    "sample_memory_dump": "",
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
        BG = "#0d1117"; CARD = "#161b22"; BORDER = "#30363d"
        FG1 = "#c9d1d9"; FG2 = "#8b949e"; CYAN = "#58a6ff"

        self.configure(bg=BG)
        style = ttk.Style(self)
        style.theme_use("clam")
        for w in ("TFrame", "TLabelframe", "TLabelframe.Label", "TNotebook", "TNotebook.Tab"):
            style.configure(w, background=BG, foreground=FG1)
        style.configure("TLabel", background=BG, foreground=FG1)
        style.configure("TEntry", fieldbackground=CARD, foreground=FG1,
                        insertcolor=FG1, bordercolor=BORDER)
        style.configure("TButton", background="#21262d", foreground=FG1,
                        bordercolor=BORDER, focusthickness=0)
        style.map("TButton", background=[("active", BORDER)])
        style.configure("Start.TButton", background="#238636", foreground="#fff")
        style.map("Start.TButton", background=[("active", "#2ea043"), ("disabled", "#21262d")])
        style.configure("Stop.TButton", background="#da3633", foreground="#fff")
        style.map("Stop.TButton", background=[("active", "#f85149"), ("disabled", "#21262d")])
        style.configure("TNotebook.Tab", padding=[12, 5], font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", CARD), ("!selected", BG)],
                  foreground=[("selected", CYAN), ("!selected", FG2)])

        # ── Header ──
        hdr = tk.Frame(self, bg=CARD, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  SOC Endpoint Agent",
                 font=("Segoe UI", 16, "bold"), bg=CARD, fg=CYAN).pack(side="left", padx=18)
        self._status_dot = tk.Label(hdr, text="●", font=("Segoe UI", 18), bg=CARD, fg="#6e7681")
        self._status_dot.pack(side="right", padx=6)
        self._status_lbl = tk.Label(hdr, text="Stopped", font=("Segoe UI", 11),
                                    bg=CARD, fg="#6e7681")
        self._status_lbl.pack(side="right", padx=4)

        # ── Notebook (tabs) ──
        nb = ttk.Notebook(self)
        nb.pack(fill="x", padx=16, pady=(10, 0))

        # ─── Tab 1: Connection ───
        conn_tab = tk.Frame(nb, bg=BG)
        nb.add(conn_tab, text="  Connection  ")

        def _lbl(parent, text, row, col=0):
            tk.Label(parent, text=text, bg=BG, fg=FG2,
                     font=("Segoe UI", 9)).grid(row=row, column=col, sticky="w", pady=5, padx=(0,4))

        _lbl(conn_tab, "Server URL", 0)
        self._url_var = tk.StringVar(value=self._cfg.get("server_url", ""))
        url_entry = ttk.Entry(conn_tab, textvariable=self._url_var, width=52)
        url_entry.grid(row=0, column=1, sticky="ew", padx=(4, 0), pady=5)

        _lbl(conn_tab, "Auth Token", 1)
        self._token_var = tk.StringVar(value=self._cfg.get("auth_token", ""))
        token_entry = ttk.Entry(conn_tab, textvariable=self._token_var, width=52, show="●")
        token_entry.grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=5)
        self._show_token = False
        def _toggle_token():
            self._show_token = not self._show_token
            token_entry.config(show="" if self._show_token else "●")
            show_btn.config(text="Hide" if self._show_token else "Show")
        show_btn = ttk.Button(conn_tab, text="Show", width=5, command=_toggle_token)
        show_btn.grid(row=1, column=2, padx=(6, 0))

        _lbl(conn_tab, "Poll interval (s)", 2)
        self._poll_var = tk.StringVar(value=str(self._cfg.get("poll_interval", 5)))
        ttk.Entry(conn_tab, textvariable=self._poll_var, width=8).grid(
            row=2, column=1, sticky="w", padx=(4, 0), pady=5)

        conn_tab.columnconfigure(1, weight=1)
        for i in range(3): conn_tab.rowconfigure(i, pad=2)
        conn_tab.configure(padx=14, pady=10)

        # ─── Tab 2: Tools ───
        tools_tab = tk.Frame(nb, bg=BG, padx=14, pady=10)
        nb.add(tools_tab, text="  Forensic Tools  ")

        def _browse_file(var, title, filetypes):
            path = filedialog.askopenfilename(title=title, filetypes=filetypes)
            if path:
                var.set(path)

        def _browse_dir(var, title):
            path = filedialog.askdirectory(title=title)
            if path:
                var.set(path)

        def _tool_row(parent, label, row, var, hint, is_file=True, filetypes=None):
            tk.Label(parent, text=label, bg=BG, fg=FG2,
                     font=("Segoe UI", 9)).grid(row=row*2, column=0, sticky="w", pady=(8,0))
            tk.Label(parent, text=hint, bg=BG, fg="#6e7681",
                     font=("Segoe UI", 8)).grid(row=row*2+1, column=0, columnspan=3,
                                                 sticky="w", pady=(0,4))
            ttk.Entry(parent, textvariable=var, width=44).grid(
                row=row*2, column=1, sticky="ew", padx=(8, 4), pady=(8,0))
            cmd = (lambda v=var, ft=filetypes: _browse_file(v, label, ft or [("All","*")])) \
                  if is_file else (lambda v=var: _browse_dir(v, label))
            ttk.Button(parent, text="Browse", command=cmd, width=7).grid(
                row=row*2, column=2, padx=(0,0), pady=(8,0))

        # YARA status (bundled — no path needed)
        tk.Label(tools_tab, text="YARA Scanner", bg=BG, fg=FG2,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", pady=(8,0))
        self._yara_status = tk.Label(tools_tab, bg=BG, fg="#3fb950",
                                     font=("Segoe UI", 9))
        self._yara_status.grid(row=0, column=1, sticky="w", padx=(8,0), pady=(8,0))
        tk.Label(tools_tab, text="Bundled into this app — no setup needed",
                 bg=BG, fg="#6e7681", font=("Segoe UI", 8)).grid(
                 row=1, column=0, columnspan=3, sticky="w", pady=(0,4))

        # Volatility status (bundled)
        tk.Label(tools_tab, text="Volatility3", bg=BG, fg=FG2,
                 font=("Segoe UI", 9)).grid(row=2, column=0, sticky="w", pady=(8,0))
        self._vol_status = tk.Label(tools_tab, bg=BG, fg="#3fb950",
                                    font=("Segoe UI", 9))
        self._vol_status.grid(row=2, column=1, sticky="w", padx=(8,0), pady=(8,0))
        tk.Label(tools_tab, text="Bundled into this app — no setup needed",
                 bg=BG, fg="#6e7681", font=("Segoe UI", 8)).grid(
                 row=3, column=0, columnspan=3, sticky="w", pady=(0,4))

        # Ghidra path
        self._ghidra_var = tk.StringVar(value=self._cfg.get("ghidra_path", ""))
        _tool_row(tools_tab, "Ghidra (analyzeHeadless)", 2, self._ghidra_var,
                  "e.g. C:\\ghidra\\support\\analyzeHeadless.bat  — must install separately (Java required)",
                  is_file=True,
                  filetypes=[("Batch/Shell","*.bat *.sh"), ("All files","*.*")])

        # Sample binary path
        self._sample_bin_var = tk.StringVar(value=self._cfg.get("sample_binary", ""))
        _tool_row(tools_tab, "Sample Binary (optional)", 3, self._sample_bin_var,
                  "Default file used by Ghidra/YARA when no path is specified in the job",
                  is_file=True, filetypes=[("Executables","*.exe *.bin *.elf"), ("All","*.*")])

        # Sample memory dump
        self._sample_mem_var = tk.StringVar(value=self._cfg.get("sample_memory_dump", ""))
        _tool_row(tools_tab, "Sample Memory Dump (optional)", 4, self._sample_mem_var,
                  "Default .dmp/.raw file used by Volatility when no dump is specified",
                  is_file=True, filetypes=[("Memory dumps","*.dmp *.raw *.mem"), ("All","*.*")])

        tools_tab.columnconfigure(1, weight=1)

        ttk.Button(tools_tab, text="Check Tools", command=self._check_tools).grid(
            row=10, column=0, columnspan=3, pady=(14, 4), sticky="w")

        # ─── Tab 3: Real-time Monitor ───
        monitor_tab = tk.Frame(nb, bg=BG, padx=14, pady=10)
        nb.add(monitor_tab, text="  Real-time Monitor  ")

        # File watcher toggle
        self._fw_enabled = tk.BooleanVar(value=self._cfg.get("file_watcher_enabled", True))
        tk.Checkbutton(monitor_tab, text="Enable File Watcher",
                       variable=self._fw_enabled, bg=BG, fg=FG1,
                       selectcolor=CARD, activebackground=BG,
                       font=("Segoe UI", 10, "bold")).grid(
                       row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        tk.Label(monitor_tab,
                 text="Watches directories for new executables → auto-runs YARA → Ghidra if hit",
                 bg=BG, fg="#6e7681", font=("Segoe UI", 8)).grid(
                 row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        # Watched directories
        tk.Label(monitor_tab, text="Watched Directories (one per line)",
                 bg=BG, fg=FG2, font=("Segoe UI", 9)).grid(
                 row=2, column=0, columnspan=3, sticky="w")

        self._watch_dirs_text = tk.Text(monitor_tab, bg=CARD, fg=FG1,
                                        font=("Consolas", 9), height=4,
                                        insertbackground=FG1,
                                        relief="flat", bd=1)
        self._watch_dirs_text.grid(row=3, column=0, columnspan=2,
                                   sticky="ew", pady=(4, 0))
        # Pre-fill with defaults
        default_dirs = self._cfg.get("watch_dirs", "")
        if not default_dirs:
            import platform as _plat, os as _os
            if _plat.system() == "Windows":
                default_dirs = "\n".join([
                    _os.environ.get("TEMP", "C:\\Windows\\Temp"),
                    _os.path.join(_os.environ.get("USERPROFILE", ""), "Downloads"),
                ])
            else:
                default_dirs = "/tmp\n~/Downloads"
        self._watch_dirs_text.insert("1.0", default_dirs)

        def _add_watch_dir():
            path = filedialog.askdirectory(title="Add watched directory")
            if path:
                current = self._watch_dirs_text.get("1.0", "end").strip()
                self._watch_dirs_text.delete("1.0", "end")
                self._watch_dirs_text.insert("1.0", (current + "\n" + path).strip())
        ttk.Button(monitor_tab, text="+ Dir", command=_add_watch_dir, width=6).grid(
            row=3, column=2, sticky="nw", padx=(6, 0), pady=(4, 0))

        monitor_tab.columnconfigure(1, weight=1)

        # Process monitor toggle
        tk.Frame(monitor_tab, bg=BORDER, height=1).grid(
            row=4, column=0, columnspan=3, sticky="ew", pady=12)

        self._pm_enabled = tk.BooleanVar(value=self._cfg.get("process_monitor_enabled", True))
        tk.Checkbutton(monitor_tab, text="Enable Process Monitor",
                       variable=self._pm_enabled, bg=BG, fg=FG1,
                       selectcolor=CARD, activebackground=BG,
                       font=("Segoe UI", 10, "bold")).grid(
                       row=5, column=0, columnspan=3, sticky="w", pady=(0, 4))
        tk.Label(monitor_tab,
                 text="Detects suspicious new processes (LOLBins, Office→shell, obfuscated PS1)",
                 bg=BG, fg="#6e7681", font=("Segoe UI", 8)).grid(
                 row=6, column=0, columnspan=3, sticky="w", pady=(0, 10))

        tk.Label(monitor_tab, text="Suspicion threshold (0-100)",
                 bg=BG, fg=FG2, font=("Segoe UI", 9)).grid(
                 row=7, column=0, sticky="w")
        self._pm_threshold = tk.StringVar(value=str(self._cfg.get("pm_threshold", 40)))
        ttk.Entry(monitor_tab, textvariable=self._pm_threshold, width=6).grid(
            row=7, column=1, sticky="w", padx=(8, 0))
        tk.Label(monitor_tab, text="(lower = more alerts)",
                 bg=BG, fg="#6e7681", font=("Segoe UI", 8)).grid(
                 row=7, column=2, sticky="w", padx=(6, 0))

        # ── Buttons ──
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill="x", padx=16, pady=8)
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
        info_frame = tk.Frame(self, bg=BG)
        info_frame.pack(fill="x", padx=16, pady=(0, 4))
        agent_id = _get_or_create_agent_id()
        for txt in [f"ID: {agent_id}", f"Host: {socket.gethostname()}",
                    f"OS: {platform.system()} {platform.release()}"]:
            tk.Label(info_frame, text=txt, bg=CARD, fg=FG2,
                     font=("Consolas", 9), padx=8, pady=3).pack(side="left", padx=(0, 6))

        # ── Log area ──
        log_frame = ttk.LabelFrame(self, text=" Agent Log ", padding=4)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(4, 14))
        self._log_box = scrolledtext.ScrolledText(
            log_frame, bg=BG, fg=FG1, font=("Consolas", 10),
            state="disabled", wrap="word", bd=0, relief="flat",
            insertbackground=FG1)
        self._log_box.pack(fill="both", expand=True)
        self._log_box.tag_config("ok",   foreground="#3fb950")
        self._log_box.tag_config("err",  foreground="#f85149")
        self._log_box.tag_config("warn", foreground="#d29922")
        self._log_box.tag_config("info", foreground="#58a6ff")
        self._log_box.tag_config("dim",  foreground="#6e7681")

        # Check tool availability on startup
        self.after(500, self._check_tools)

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

    def _check_tools(self):
        """Check which forensic tools are available and update the Tools tab labels."""
        import shutil, importlib

        # YARA
        try:
            importlib.import_module("yara")
            self._yara_status.config(text="✓ Available", fg="#3fb950")
        except ImportError:
            self._yara_status.config(text="✗ Not installed (pip install yara-python)", fg="#f85149")

        # Volatility3
        try:
            importlib.import_module("volatility3")
            self._vol_status.config(text="✓ Available", fg="#3fb950")
        except ImportError:
            self._vol_status.config(text="✗ Not installed (pip install volatility3)", fg="#f85149")

        # Ghidra — just check if path is set and exists
        ghidra = self._ghidra_var.get().strip()
        if ghidra and Path(ghidra).exists():
            self._append_log(f"✓ Ghidra found: {ghidra}")
        elif ghidra:
            self._append_log(f"✗ Ghidra path not found: {ghidra}")
        else:
            self._append_log("  Ghidra: not configured (binary RE will use strings fallback)")

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

        ghidra = self._ghidra_var.get().strip()
        sample_bin = self._sample_bin_var.get().strip()
        sample_mem = self._sample_mem_var.get().strip()

        # Apply tool paths to env so endpoint_agent modules pick them up
        if ghidra:
            os.environ["GHIDRA_HEADLESS"] = ghidra
        if sample_bin:
            os.environ["SAMPLE_BINARY"] = sample_bin
        if sample_mem:
            os.environ["SAMPLE_MEMORY_DUMP"] = sample_mem

        watch_dirs = [d.strip() for d in
                      self._watch_dirs_text.get("1.0", "end").strip().splitlines()
                      if d.strip()]
        fw_enabled = self._fw_enabled.get()
        pm_enabled = self._pm_enabled.get()
        try:
            pm_threshold = int(self._pm_threshold.get())
        except ValueError:
            pm_threshold = 40

        if ghidra:
            os.environ["GHIDRA_HEADLESS"] = ghidra
        if sample_bin:
            os.environ["SAMPLE_BINARY"] = sample_bin
        if sample_mem:
            os.environ["SAMPLE_MEMORY_DUMP"] = sample_mem
        os.environ["AGENT_FW_ENABLED"] = "1" if fw_enabled else "0"
        os.environ["AGENT_PM_ENABLED"] = "1" if pm_enabled else "0"
        os.environ["AGENT_PM_THRESHOLD"] = str(pm_threshold)
        os.environ["AGENT_WATCH_DIRS"] = ":".join(watch_dirs)

        save_config({
            "server_url": url, "auth_token": token, "poll_interval": poll,
            "ghidra_path": ghidra, "sample_binary": sample_bin,
            "sample_memory_dump": sample_mem,
            "file_watcher_enabled": fw_enabled,
            "process_monitor_enabled": pm_enabled,
            "pm_threshold": pm_threshold,
            "watch_dirs": "\n".join(watch_dirs),
        })

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


def _ensure_admin():
    """Re-launch the process with UAC elevation if not already admin (Windows only)."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return  # already admin
        # Re-launch with elevation
        import ctypes
        params = " ".join(f'"{a}"' for a in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)
    except Exception:
        pass  # non-Windows or elevation unavailable — continue anyway


def main():
    _ensure_admin()
    app = AgentApp()
    app.mainloop()


if __name__ == "__main__":
    main()
