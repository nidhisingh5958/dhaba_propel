"""
FastAPI application for Dhaba Support Ticket Triage.

Endpoints:
- POST /triage: End-to-end ticket triage with idempotency, LLM draft,
  deterministic money gate, and audit logging.
- GET /health: Health check and service metadata.
"""

from typing import Optional
from fastapi import FastAPI, HTTPException, Response, status

from app.config import settings
from app.idempotency import (
    IdempotencyConflictError,
    IdempotencyStore,
    compute_payload_hash,
)
from app.llm_client import TriageLLMClient
from app.logger import log_event
from app.money_gate import apply_safety_gates
from app.schemas import TicketInput, TriageResponse

app = FastAPI(
    title="Dhaba Support Triage API",
    description="Automated support ticket triage with deterministic financial safety gates.",
    version="0.1.0",
)

# Default shared service instances (can be overridden via app.state in tests)
default_store = IdempotencyStore()
default_llm = TriageLLMClient()


def get_store() -> IdempotencyStore:
    return getattr(app.state, "idempotency_store", default_store)


def get_llm_client() -> TriageLLMClient:
    return getattr(app.state, "llm_client", default_llm)


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint exposing runtime operational mode."""
    llm = get_llm_client()
    return {
        "status": "ok",
        "service": "dhaba-triage",
        "version": "0.1.0",
        "triage_mode": llm.mode,
        "confidence_threshold": settings.CONFIDENCE_THRESHOLD,
    }


@app.post(
    "/triage",
    response_model=TriageResponse,
    status_code=status.HTTP_200_OK,
    tags=["Triage"],
    responses={
        200: {"description": "Ticket successfully triaged or replayed from cache."},
        409: {"description": "Idempotency conflict: Ticket ID re-submitted with differing payload."},
    },
)
def triage_ticket(ticket: TicketInput, response: Response) -> TriageResponse:
    """
    Triages an incoming customer support ticket.
    
    Processing Steps:
    1. Compute canonical SHA-256 payload hash.
    2. Check IdempotencyStore. If previously triaged with identical payload, return cached
       response with header X-Idempotent-Replay: true. If payload differs, return HTTP 409.
    3. Generate LLMTriageDraft via TriageLLMClient (with validation, 1x retry, and degradation).
    4. Pass draft through apply_safety_gates (Money Gate, Injection Blockers, Confidence Cap).
    5. Save final result into atomic SQLite ledger.
    6. Emit structured, PII-scrubbed audit log event.
    7. Return TriageResponse with header X-Idempotent-Replay: false.
    """
    store = get_store()
    llm = get_llm_client()

    payload_hash = compute_payload_hash(ticket)

    # 1. Idempotency Check
    try:
        cached = store.get_existing(ticket.id, payload_hash)
        if cached:
            response.headers["X-Idempotent-Replay"] = "true"
            log_event(
                event_type="idempotent_replay_hit",
                ticket_id=ticket.id,
                refund_approved=cached.refund.approved,
                refund_amount=cached.refund.amount_inr,
            )
            return cached
    except IdempotencyConflictError as err:
        log_event(
            event_type="idempotency_conflict_rejected",
            ticket_id=ticket.id,
            conflict_reason=str(err),
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err

    # 2. LLM Draft Generation (with validation, retry & fallback)
    llm_draft = llm.triage(ticket)

    # 3. Deterministic Safety Gate Evaluation
    final_response = apply_safety_gates(ticket, llm_draft)

    # 4. Atomic Ledger Persistence
    store.save_result(ticket.id, payload_hash, final_response)

    # 5. PII-Safe Event Logging
    log_event(
        event_type="ticket_triage_completed",
        ticket_id=ticket.id,
        category=final_response.category.value,
        severity=final_response.severity.value,
        refund_approved=final_response.refund.approved,
        refund_amount=final_response.refund.amount_inr,
        needs_human=final_response.needs_human,
        confidence=final_response.confidence,
    )

    # 6. Response Header
    response.headers["X-Idempotent-Replay"] = "false"
    return final_response

