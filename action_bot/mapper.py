"""
Hybrid mapper: rules first (fast, deterministic), LLM fallback only if rules
match nothing for a given recommendation string.
"""
from __future__ import annotations

import json
import re
from shared.schemas import AnalysisReport
from shared.llm_client import LLMClient
from shared.logger import get_logger

log = get_logger(__name__)


ISOLATE_PATTERNS = [r"\bisolat", r"\bquarantine\b.+\b(endpoint|host|machine)\b",
                    r"\bdisconnect\b.+\bnetwork\b", r"contain"]
# Use lazy quantifiers ({0,N}?) so the match doesn't greedily consume leading digits of the IP
BLOCK_IP_PATTERNS = [
    r"block.{0,30}?(?:outbound|connection|traffic).{0,30}?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"block.{0,30}?ip.{0,30}?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"firewall.{0,30}?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    # bare "block <IP>" with no keyword (e.g. "block 185.220.101.45 and domain ...")
    r"block\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
]
# Allow up to 80 chars between "block" and "domain/hostname" (handles "block <ip> and domain <dom>")
BLOCK_DOMAIN_PATTERNS = [
    r"block.{0,80}?(?:domain|hostname).{0,30}?(?P<dom>[a-z0-9][a-z0-9.-]*\.[a-z]{2,})",
]
QUARANTINE_FILE_PATTERNS = [r"quarantine.{0,30}(?:file|binary|payload)",
                            r"isolate.{0,20}file"]
# Use lazy quantifier + require at least 3 chars for username to avoid partial matches
DISABLE_USER_PATTERNS = [r"disable.{0,20}(?:user|account).{0,30}?\s(?P<user>[\w][\w.-]{2,})",
                         r"lock.{0,20}(?:user|account).{0,30}?\s(?P<user>[\w][\w.-]{2,})"]
SUSPEND_PROCESS_PATTERNS = [r"suspend.{0,20}process",
                            r"snapshot.{0,20}process",
                            r"freeze.{0,20}process"]


def _try_rules(recommendation: str, report: AnalysisReport) -> list[dict]:
    text = recommendation.lower()
    out: list[dict] = []
    blob = recommendation + " " + (report.summary or "") + " " + " ".join(
        f"{f.title} {f.evidence}" for f in (report.findings or [])
    )

    if any(re.search(p, text) for p in ISOLATE_PATTERNS):
        out.append({"name": "isolate_endpoint", "params": {},
                    "reason": recommendation, "destructive": True})

    for pat in BLOCK_IP_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            out.append({"name": "block_ip", "params": {"ip": m.group("ip")},
                        "reason": recommendation, "destructive": True})
    if "block" in text and re.search(r"\bip\b|ipv4|address", text) and not any(a["name"] == "block_ip" for a in out):
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", blob):
            out.append({"name": "block_ip", "params": {"ip": ip},
                        "reason": recommendation, "destructive": True})

    for pat in BLOCK_DOMAIN_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            out.append({"name": "block_domain", "params": {"domain": m.group("dom")},
                        "reason": recommendation, "destructive": True})

    if any(re.search(p, text) for p in QUARANTINE_FILE_PATTERNS):
        paths = re.findall(r"(?:[a-zA-Z]:\\|/)[^\s\"']+", recommendation)
        if not paths:
            paths = re.findall(r"(?:[a-zA-Z]:\\|/)[^\s\"']+", blob)
        for p in paths[:5]:
            out.append({"name": "quarantine_file", "params": {"path": p},
                        "reason": recommendation, "destructive": True})

    for pat in DISABLE_USER_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            out.append({"name": "disable_user", "params": {"username": m.group("user")},
                        "reason": recommendation, "destructive": True})

    if any(re.search(p, text) for p in SUSPEND_PROCESS_PATTERNS):
        pid_match = re.search(r"pid[\s=:]*(\d+)", text)
        params = {"pid": int(pid_match.group(1))} if pid_match else {}
        out.append({"name": "snapshot_process", "params": params,
                    "reason": recommendation, "destructive": False})

    return out


SYSTEM_PROMPT = """\
You convert a single free-text remediation recommendation into ONE OR MORE
structured action requests. Available actions (evidence-preserving only):

- isolate_endpoint        params: {}
- unisolate_endpoint      params: {}
- block_ip                params: {"ip": "<ipv4>"}
- unblock_ip              params: {"ip": "<ipv4>"}
- block_domain            params: {"domain": "<hostname>"}
- quarantine_file         params: {"path": "<absolute path>"}
- disable_user            params: {"username": "<local user>"}
- snapshot_process        params: {"pid": <int>}

Rules:
- ONLY act on what the recommendation text EXPLICITLY instructs — do NOT infer actions
  from the summary or findings context.
- Return [] for recommendations about: investigation, forensic analysis, disk imaging,
  log review, user training, reporting, policy changes, or anything not directly mapping
  to the available actions above.
- IPs and domains must appear IN THE RECOMMENDATION TEXT itself, not just in the context.
- Never propose process kill, file delete, reboot, or disk format.
- If the recommendation is vague or does not map to an available action, return [].

Return ONLY a JSON array of {name, params} objects. Wrap in {"actions": [...]} if needed.
"""


def _llm_map(recommendation: str, report: AnalysisReport,
             llm: LLMClient | None = None) -> list[dict]:
    llm = llm or LLMClient()
    context = f"Recommendation: {recommendation}\n\nAnalysis summary: {report.summary}\n\nFindings: {json.dumps([f.model_dump() for f in (report.findings or [])], indent=2, default=str)}"
    try:
        parsed = llm.generate_json(SYSTEM_PROMPT, context)
        if isinstance(parsed, dict):
            parsed = parsed.get("actions", []) or parsed.get("items", [])
        result = []
        for a in parsed or []:
            if not isinstance(a, dict) or "name" not in a:
                continue
            result.append({
                "name": a["name"], "params": a.get("params", {}),
                "reason": recommendation,
                "destructive": a["name"] not in ("snapshot_process",),
            })
        return result
    except Exception as e:
        log.warning(f"LLM mapper failed: {e}")
        return []


def map_recommendations(report: AnalysisReport) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for rec in (report.recommended_actions or []):
        candidates = _try_rules(rec, report)
        if not candidates:
            log.info(f"No rule match for: {rec!r} — LLM fallback")
            candidates = _llm_map(rec, report)
        for c in candidates:
            key = (c["name"], json.dumps(c["params"], sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
    log.info(f"Mapped {len(report.recommended_actions or [])} recommendations to {len(out)} actions")
    return out
