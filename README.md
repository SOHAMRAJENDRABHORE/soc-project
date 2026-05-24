# Agentic AI for Endpoint Security

A multi-agent SOC pipeline:

- **Decision Bot** ✅ — triages alerts, extracts IOCs, enriches via threat intel, produces a verdict.
- **Analysis Bot** ✅ — orchestrates forensics via lightweight endpoint agents (real Volatility + Ghidra).
- **Action Bot** ✅ — remediation (isolate, kill, block).
- **Onboarding Agent** 🔜 — pulls alerts from Microsoft Graph API.

## Architecture

```
┌─ Your laptop ─────────────────────────────────┐         ┌─ Endpoint VM ─────────┐
│                                               │         │                       │
│  Streamlit UI ──► Decision Bot                │         │  Endpoint Agent       │
│                                               │  poll   │  ├─ processes        │
│  Streamlit UI ──► Analysis Bot ──► Central ◄──┼─────────┤  ├─ network          │
│                                    Server     │   HTTP  │  ├─ persistence      │
│                                    (FastAPI   │         │  ├─ file_inspect     │
│                                     + SQLite) │         │  ├─ memory (Vol3)    │
│                                               │         │  └─ binary_re (Ghidra)│
└───────────────────────────────────────────────┘         └───────────────────────┘
```

## Setup (one-time)

Requirements: Python 3.10+

### Linux / macOS (quick start)

```bash
# One-liner setup + start
bash start_linux.sh setup
bash start_linux.sh server    # terminal 1 — central server on :8080
bash start_linux.sh agent     # terminal 2 — endpoint agent
# Or start both in background:
bash start_linux.sh all
```

### Manual setup (Linux/macOS/Windows)

```bash
# 1. Venv
python3 -m venv .venv                    # Linux/macOS
# python -m venv .venv                   # Windows

# 2. Activate
source .venv/bin/activate                # Linux/macOS
# .venv\Scripts\Activate.ps1            # Windows (PowerShell)

# 3. Install
pip install -r requirements.txt

# 4. Configure
cp .env.example .env   # or: copy .env.example .env  (Windows)
# Edit .env — at minimum set AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT and AGENT_AUTH_TOKEN
python3 -c "import secrets; print(secrets.token_urlsafe(32))"  # → use as AGENT_AUTH_TOKEN
```

## How to run (3 processes, 2 machines)

### Machine 1 — your laptop (server + UI)

Open **terminal 1** (the central server):
```bash
# Linux/macOS:
python3 -m uvicorn central_server.server:app --host 0.0.0.0 --port 8080
# Windows:
python -m uvicorn central_server.server:app --host 0.0.0.0 --port 8080
```
You should see `Central server ready`. Open http://localhost:8080/ui/ for the dashboard.

### Machine 2 — the endpoint VM (the thing being protected)

1. Clone the repo onto the VM (or copy it over).
2. `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. Copy your `.env` over **and edit one line**:
   ```
   CENTRAL_SERVER_URL=http://<your-laptop-IP>:8080
   ```
4. Make sure both machines are on the same network (VirtualBox: use "Bridged Adapter").
5. Start the agent:
   ```bash
   python3 -m endpoint_agent.agent
   ```
6. You should see it register with the central server. The agent appears as online in the dashboard.

## Demo flow

1. **Decision Bot page** → pick "Possible ransomware activity" → run.
2. **Analysis Bot page** → verdict auto-loaded from session → pick your VM → run.
3. The agent on the VM runs `processes`, `network`, `persistence`, and (if configured) `memory_dump` and `binary_re`.
4. LLM produces a structured AnalysisReport with findings, severity, and recommended actions.

## Volatility & Ghidra setup (on the agent machine)

### Volatility 3
Volatility3 is **optional** and only needed on the endpoint agent machine (not the server).
Install it separately:
```bash
pip install volatility3
```
You also need a memory dump file. For the demo, grab a free sample:
- https://github.com/volatilityfoundation/volatility3/wiki/Symbol-Tables (test images)
- https://www.memoryanalysis.net/amf (Andrew Case's sample dumps)

Then in the agent's `.env`:
```
SAMPLE_MEMORY_DUMP=/path/to/sample.vmem
```

### Ghidra
1. Download from https://ghidra-sre.org/
2. Install Java JDK 17+
3. On the agent's `.env`:
   ```
   GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
   SAMPLE_BINARY=/usr/bin/ls            # any safe binary works
   ```

If Ghidra isn't configured, the agent falls back to a `strings` extraction so you still get useful output.

## Where to get API keys

| Service | URL | Notes |
|---|---|---|
| Azure OpenAI | Azure Portal | Subscription required |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 1000/day |
| OTX | https://otx.alienvault.com/api | Generous |

## Project layout

```
agentic-soc/
├── shared/                # schemas, LLM client, config, logger
├── decision_bot/          # ✅ alert → verdict
├── analysis_bot/          # ✅ verdict → analysis report
│   ├── action_planner.py
│   ├── dispatcher.py
│   ├── synthesis.py
│   └── bot.py
├── central_server/        # ✅ FastAPI; agents poll, Analysis Bot dispatches
│   ├── db.py
│   └── server.py
├── endpoint_agent/        # ✅ runs on each endpoint
│   ├── agent.py
│   └── modules/
│       ├── processes.py
│       ├── network.py
│       ├── persistence.py
│       ├── file_inspect.py
│       ├── memory.py      # real Volatility 3
│       └── binary_re.py   # real Ghidra headless
├── action_bot/            # ✅ remediation executor
├── onboarding_agent/      # 🔜
└── frontend/
    ├── streamlit_app.py   # Decision Bot page
    ├── pages/1_Analysis_Bot.py
    └── _components/       # shared styling + widgets
```

## Adding things later

- **New threat intel source** → subclass `BaseEnricher` in `decision_bot/enrichment/`, register in orchestrator.
- **New forensic action** → write a function in `endpoint_agent/modules/`, register in `modules/__init__.py`. The agent's capabilities update automatically.
- **Swap LLM** → change `shared/llm_client.py` only.
