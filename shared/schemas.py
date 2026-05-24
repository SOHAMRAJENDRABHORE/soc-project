"""
Pydantic schemas. These are the contracts between bots.

Decision Bot consumes Alert, produces Verdict.
Analysis Bot will consume Verdict, produce AnalysisReport.
Action Bot will consume AnalysisReport, produce ActionPlan.

Keeping all schemas here means every bot sees the same shape.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------- Input ----------

class Alert(BaseModel):
    """Raw alert as it arrives (from Graph API later, or pasted manually now)."""
    alert_id: str
    source: str = "manual"            # "graph_api" | "manual" | "edr" | etc.
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: Optional[str] = None    # "low" | "medium" | "high" | "critical"
    title: Optional[str] = None
    description: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)  # original payload
    endpoint_id: Optional[str] = None  # which device this is about


# ---------- IOCs ----------

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    COMMAND_LINE = "command_line"
    FILE_PATH = "file_path"


class IOC(BaseModel):
    type: IOCType
    value: str
    context: Optional[str] = None  # where in the alert this came from


# ---------- Enrichment ----------

class EnrichmentResult(BaseModel):
    """Result from one threat intel source for one IOC."""
    source: str                   # "virustotal" | "abuseipdb" | "otx"
    ioc_value: str
    ioc_type: IOCType
    success: bool
    raw_response: dict[str, Any] = Field(default_factory=dict)
    # Normalized signals (every enricher fills what it can):
    malicious_score: Optional[float] = None    # 0-100
    reputation: Optional[str] = None           # "clean" | "suspicious" | "malicious"
    tags: list[str] = Field(default_factory=list)
    summary: Optional[str] = None              # human-readable one-liner
    error: Optional[str] = None


# ---------- Verdict (Decision Bot's output) ----------

class VerdictLabel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Verdict(BaseModel):
    """Decision Bot's final output. Consumed by Analysis Bot next."""
    alert_id: str
    label: VerdictLabel
    confidence: int = Field(ge=0, le=100)        # 0-100
    reasoning: str                                # LLM's explanation
    mitre_techniques: list[str] = Field(default_factory=list)  # e.g. ["T1059.001"]
    kill_chain_phase: Optional[str] = None
    recommended_next_step: str                    # instruction for Analysis Bot
    iocs: list[IOC] = Field(default_factory=list)
    enrichment: list[EnrichmentResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    llm_model: Optional[str] = None


# ---------- Endpoint Agent contract ----------

class AgentRegistration(BaseModel):
    """Agent → server on first start."""
    agent_id: str
    hostname: str
    os: str                # "Linux" | "Windows" | "Darwin"
    os_version: str
    agent_version: str
    capabilities: list[str] = Field(default_factory=list)  # which actions it supports


class Heartbeat(BaseModel):
    agent_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "alive"


class JobStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"
    EXPIRED = "expired"


class ForensicAction(BaseModel):
    """One thing to do on the endpoint."""
    name: str                              # "processes" | "network" | "memory_dump" | ...
    params: dict[str, Any] = Field(default_factory=dict)


class Job(BaseModel):
    """A unit of work the server hands to an agent."""
    job_id: str
    agent_id: str
    actions: list[ForensicAction]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: JobStatus = JobStatus.QUEUED
    requested_by: Optional[str] = None     # e.g., "analysis_bot:alert_id=DEMO-001"


class ActionResult(BaseModel):
    """Output of one forensic action."""
    action: str
    success: bool
    duration_seconds: float
    data: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class JobResult(BaseModel):
    """Agent → server when a job is done."""
    job_id: str
    agent_id: str
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    results: list[ActionResult] = Field(default_factory=list)


# ---------- Analysis Bot output ----------

class Finding(BaseModel):
    """One concrete observation from forensics."""
    category: str                          # "process" | "network" | "persistence" | "memory" | "binary"
    severity: str                          # "low" | "medium" | "high" | "critical"
    title: str
    evidence: str                          # what we actually saw
    mitre_techniques: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Analysis Bot's output. Consumed by Action Bot next."""
    alert_id: str
    endpoint_id: Optional[str]
    job_id: str
    verdict_label: VerdictLabel            # carried forward from Decision Bot
    findings: list[Finding] = Field(default_factory=list)
    overall_severity: str                  # "low" | "medium" | "high" | "critical"
    summary: str                           # LLM-written narrative
    recommended_actions: list[str] = Field(default_factory=list)   # for Action Bot
    raw_telemetry: list[ActionResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    llm_model: Optional[str] = None


# ---------- Onboarding Agent ----------

class ProviderType(str, Enum):
    MOCK = "mock"
    GRAPH = "graph"            # not yet implemented; UI shows as "requires credentials"
    WEBHOOK = "webhook"


class IngestionMode(str, Enum):
    INBOX = "inbox"            # alerts queue, analyst clicks to triage
    AUTO = "auto"              # alerts run through Decision Bot immediately


class Tenant(BaseModel):
    """One onboarded organization."""
    tenant_id: str
    display_name: str
    provider_type: ProviderType
    ingestion_mode: IngestionMode = IngestionMode.INBOX
    enabled: bool = True
    # Provider-specific config. For mock: {"alert_file": "acme_corp.json"}
    # For graph: {"azure_tenant_id": "...", "client_id": "..."} + encrypted secret
    # For webhook: {"token": "..."} (token is the URL segment they POST to)
    provider_config: dict[str, Any] = Field(default_factory=dict)
    # Encrypted credentials (Fernet ciphertext). Stored separately to keep raw out of dumps.
    encrypted_credentials: Optional[str] = None
    last_polled_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PendingAlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"        # picked up by analyst, sent to Decision Bot
    AUTO_PROCESSED = "auto_processed"
    DISMISSED = "dismissed"


class PendingAlert(BaseModel):
    """An alert ingested by Onboarding Agent, waiting in the inbox or auto-processed."""
    pending_id: str
    tenant_id: str
    tenant_name: str                       # denormalized for UI convenience
    alert: Alert                           # the normalized alert ready for Decision Bot
    raw_provider_payload: dict[str, Any] = Field(default_factory=dict)  # original Graph-shaped data
    status: PendingAlertStatus = PendingAlertStatus.NEW
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # If auto-processed, link to the verdict
    verdict_alert_id: Optional[str] = None
    auto_result_summary: Optional[str] = None
