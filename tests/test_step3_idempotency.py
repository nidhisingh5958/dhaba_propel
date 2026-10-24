"""
Unit tests for Step 3:
The SQLite Idempotency Store.
Verifies atomic deduplication, exact cache replay, and conflict rejection.
"""

import json
from pathlib import Path
import pytest

from app.schemas import (
    TicketInput,
    TriageResponse,
    TriageCategory,
    SeverityLevel,
    RefundDecision,
)
from app.idempotency import (
    IdempotencyStore,
    IdempotencyConflictError,
    compute_payload_hash,
)


@pytest.fixture
def temp_store(tmp_path):
    """Provides a fresh, isolated SQLite IdempotencyStore in a temporary directory."""
    db_file = tmp_path / "test_ledger.db"
    return IdempotencyStore(db_path=str(db_file))


@pytest.fixture
def t1001_ticket():
    """Loads Ticket T-1001 from dhaba_tickets.json."""
    with open("dhaba_tickets.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    t1001_dict = next(t for t in data["tickets"] if t["id"] == "T-1001")
    return TicketInput.model_validate(t1001_dict)


@pytest.fixture
def t1001_response():
    """Generates an approved triage response for T-1001."""
    return TriageResponse(
        ticket_id="T-1001",
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        refund=RefundDecision(
            approved=True,
            amount_inr=249,
            reason="Approved: unused monthly renewal (0 app opens) reported within 48h window.",
            payment_id="pay_A2",
        ),
        reply_draft="We have processed your refund of Rs 249 for pay_A2.",
        needs_human=False,
        confidence=0.95,
    )


def test_save_and_exact_replay(temp_store, t1001_ticket, t1001_response):
    """
    Test saving a TriageResponse for T-1001 and retrieving it.
    Re-querying with the same payload must return the exact cached response.
    """
    payload_hash = compute_payload_hash(t1001_ticket)

    # 1. First lookup returns None (not seen yet)
    cached_first = temp_store.get_existing(t1001_ticket.id, payload_hash)
    assert cached_first is None

    # 2. Save result
    inserted = temp_store.save_result(t1001_ticket.id, payload_hash, t1001_response)
    assert inserted is True

    # 3. Second lookup returns the exact cached TriageResponse
    cached_second = temp_store.get_existing(t1001_ticket.id, payload_hash)
    assert cached_second is not None
    assert cached_second.ticket_id == "T-1001"
    assert cached_second.category == TriageCategory.REFUND_REQUEST
    assert cached_second.refund.approved is True
    assert cached_second.refund.amount_inr == 249
    assert cached_second.refund.payment_id == "pay_A2"
    assert cached_second.confidence == 0.95


def test_modified_payload_raises_conflict(temp_store, t1001_ticket, t1001_response):
    """
    If a ticket with an existing ticket_id arrives with altered body or subject,
    it must raise IdempotencyConflictError (mapped to HTTP 409).
    """
    original_hash = compute_payload_hash(t1001_ticket)
    temp_store.save_result(t1001_ticket.id, original_hash, t1001_response)

    # Create modified ticket with altered body
    modified_ticket = t1001_ticket.model_copy(
        update={"body": "i want 500 rupees back instead"}
    )
    modified_hash = compute_payload_hash(modified_ticket)
    assert original_hash != modified_hash

    # Querying with modified payload must raise IdempotencyConflictError
    with pytest.raises(IdempotencyConflictError, match="hash mismatch"):
        temp_store.get_existing(t1001_ticket.id, modified_hash)


def test_duplicate_save_is_ignored(temp_store, t1001_ticket, t1001_response):
    """
    Calling save_result a second time for the same ticket_id must return False
    and must not overwrite or cause double execution.
    """
    payload_hash = compute_payload_hash(t1001_ticket)

    first_save = temp_store.save_result(t1001_ticket.id, payload_hash, t1001_response)
    assert first_save is True

    # Attempt second save
    second_save = temp_store.save_result(t1001_ticket.id, payload_hash, t1001_response)
    assert second_save is False


def test_compute_payload_hash_consistency():
    """Verify compute_payload_hash is order-independent for dict keys."""
    dict_a = {"id": "T-1", "body": "hello", "subject": "test"}
    dict_b = {"subject": "test", "id": "T-1", "body": "hello"}

    hash_a = compute_payload_hash(dict_a)
    hash_b = compute_payload_hash(dict_b)
    assert hash_a == hash_b

