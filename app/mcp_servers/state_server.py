import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

# Allow launching this file directly (mcp_config.json runs it as a script).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.state import StateStore  # noqa: E402
from app.plugins.guardrails import redact_pii

TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
SESSION_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

# Port 8081 and path /mcp match mcp_config.json ("state-store", streamable-http).
mcp = FastMCP("state-store", host="127.0.0.1", port=8081)
state = StateStore()
_initialized = False


async def _ready() -> None:
    global _initialized
    if not _initialized:
        await state.initialize()
        _initialized = True


def _check_tenant(tenant_id: str) -> None:
    if not TENANT_RE.fullmatch(tenant_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: tenant_id")


def _check_session(session_id: str) -> None:
    if not SESSION_RE.fullmatch(session_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: session_id")


@mcp.tool()
async def get_session_facts(session_id: str, tenant_id: str) -> list[str]:
    """Return up to the last 3 verified facts for a tenant's session."""
    _check_tenant(tenant_id)
    _check_session(session_id)
    await _ready()
    return await state.get_facts(tenant_id, session_id)


@mcp.tool()
async def save_session_fact(session_id: str, tenant_id: str, fact: str, provenance_hash: str) -> dict:
    """Persist a verified fact. Raw PII is redacted before storage; provenance must be a SHA-256 hex digest."""
    _check_tenant(tenant_id)
    _check_session(session_id)
    if not SHA256_RE.fullmatch(provenance_hash):
        raise ValueError("INVALID_TOOL_ARGUMENT: provenance_hash")
    if not 1 <= len(fact) <= 4096:
        raise ValueError("INVALID_TOOL_ARGUMENT: fact")
    await _ready()
    redacted, _ = redact_pii(fact)
    await state.save_fact(tenant_id, session_id, redacted, provenance_hash)
    return {"saved": True}


@mcp.tool()
async def create_pending_mutation(
    tenant_id: str, user_id: str, request_id: str, action: str,
    canonical_args: dict[str, Any], idempotency_key: str,
) -> dict:
    """Record a Tier 3 mutation as PENDING_APPROVAL. Requires a UUIDv4 idempotency key; returns a canonical args hash."""
    _check_tenant(tenant_id)
    if not TENANT_RE.fullmatch(user_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: user_id")
    if not UUID4_RE.fullmatch(idempotency_key):
        raise ValueError("INVALID_TOOL_ARGUMENT: idempotency_key")
    if not UUID4_RE.fullmatch(request_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: request_id")
    if not re.fullmatch(r"[a-z_]{1,64}", action):
        raise ValueError("INVALID_TOOL_ARGUMENT: action")
    await _ready()
    canonical = json.dumps(canonical_args, sort_keys=True, separators=(",", ":"))
    review_id = await state.create_pending_mutation(
        tenant_id, user_id, request_id, action, canonical_args, idempotency_key,
    )
    return {
        "review_id": review_id,
        "status": "PENDING_APPROVAL",
        "canonical_args_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


@mcp.tool()
async def approve_mutation(
    review_id: int, tenant_id: str, reviewer_id: str, decision: Literal["APPROVED", "REJECTED"],
) -> dict:
    """Record a reviewer decision on a pending mutation. Tenant-scoped; already-decided records are unchanged."""
    _check_tenant(tenant_id)
    if not TENANT_RE.fullmatch(reviewer_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: reviewer_id")
    if review_id < 1:
        raise ValueError("INVALID_TOOL_ARGUMENT: review_id")
    await _ready()
    try:
        status = await state.decide_mutation(tenant_id, review_id, reviewer_id, decision)
    except LookupError:
        raise ValueError("NOT_FOUND: review_id")
    return {"review_id": review_id, "status": status}


@mcp.tool()
async def write_audit_event(tenant_id: str, request_id: str, event: str, payload: dict[str, Any]) -> dict:
    """Append a hash-chained audit record. Payload must already be redacted; raw PII is rejected."""
    _check_tenant(tenant_id)
    if not UUID4_RE.fullmatch(request_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: request_id")
    if not re.fullmatch(r"[a-z._]{1,64}", event):
        raise ValueError("INVALID_TOOL_ARGUMENT: event")
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    redacted, found = redact_pii(serialized)
    if found:
        raise ValueError("PII_BLOCKED_OR_REDACTED: payload must be redacted before audit")
    await _ready()
    digest = await state.write_audit(tenant_id, request_id, event, payload)
    return {"hash": digest}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
