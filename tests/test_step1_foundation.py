"""
Unit tests for Step 1 Foundation:
- Dhaba ticket dataset parsing into strict Pydantic v2 schemas
- Schema validation constraints (extra='forbid', negative amounts, enums)
- PII-safe logging and custom filter redaction
"""

import io
import json
import logging
from pathlib import Path
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.schemas import (
    DhabaTicketsFile,
    TicketInput,
    Purchase,
    PurchaseType,
    PurchaseStatus,
    TriageCategory,
    SeverityLevel,
    RefundDecision,
    TriageResponse,
    LLMTriageDraft,
)
from app.logger import (
    scrub_pii,
    log_event,
    PIIScrubFilter,
    JSONLogFormatter,
    setup_logger,
)


# -----------------------------------------------------------------------------
# 1. Dataset Parsing Tests
# -----------------------------------------------------------------------------

def test_load_all_12_dhaba_tickets():
    """Verify that all 12 tickets from dhaba_tickets.json parse into TicketInput."""
    dataset_path = Path("dhaba_tickets.json")
    assert dataset_path.exists(), "dhaba_tickets.json not found in root directory"

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Validate container file structure
    container = DhabaTicketsFile.model_validate(data)
    assert len(container.tickets) == 12, f"Expected 12 tickets, found {len(container.tickets)}"

    # Validate each individual ticket as strict TicketInput
    ticket_ids = set()
    for raw_ticket in data["tickets"]:
        ticket = TicketInput.model_validate(raw_ticket)
        assert ticket.id.startswith("T-10")
        assert isinstance(ticket.subject, str)
        assert isinstance(ticket.body, str)
        assert isinstance(ticket.purchases, list)
        assert ticket.app_opens_since_renewal >= 0
        ticket_ids.add(ticket.id)

        # Validate purchases
        for p in ticket.purchases:
            assert isinstance(p, Purchase)
            assert p.amount_inr >= 0
            assert p.type in {PurchaseType.TRIAL, PurchaseType.RENEWAL}
            assert p.status in {
                PurchaseStatus.INITIATED,
                PurchaseStatus.FAILED,
                PurchaseStatus.SUCCESSFUL,
                PurchaseStatus.RENEWAL,
            }

    assert len(ticket_ids) == 12, "All 12 ticket IDs must be unique"


def test_ticket_t1001_details():
    """Verify specific fields for Ticket T-1001."""
    with open("dhaba_tickets.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    t1001_raw = next(t for t in data["tickets"] if t["id"] == "T-1001")
    ticket = TicketInput.model_validate(t1001_raw)

    assert ticket.id == "T-1001"
    assert "charged 249" in ticket.subject
    assert len(ticket.purchases) == 2
    assert ticket.purchases[0].id == "pay_A1"
    assert ticket.purchases[0].amount_inr == 1
    assert ticket.purchases[0].type == PurchaseType.TRIAL
    assert ticket.purchases[1].id == "pay_A2"
    assert ticket.purchases[1].amount_inr == 249
    assert ticket.purchases[1].type == PurchaseType.RENEWAL
    assert ticket.app_opens_since_renewal == 0


# -----------------------------------------------------------------------------
# 2. Strict Schema Validation Tests
# -----------------------------------------------------------------------------

def test_extra_fields_forbidden():
    """Verify extra='forbid' raises ValidationError when unexpected keys are passed."""
    # Extra field on Purchase
    with pytest.raises(ValidationError):
        Purchase(
            id="pay_99",
            type=PurchaseType.TRIAL,
            amount_inr=1,
            status=PurchaseStatus.SUCCESSFUL,
            at="2026-09-01T10:00:00+05:30",
            extra_field="malicious_payload",  # type: ignore[call-arg]
        )

    # Extra field on TicketInput
    with pytest.raises(ValidationError):
        TicketInput(
            id="T-9999",
            received_at="2026-09-01T10:00:00+05:30",
            subject="Test",
            body="Test body",
            purchases=[],
            app_opens_since_renewal=0,
            injected_admin_override=True,  # type: ignore[call-arg]
        )

    # Extra field on RefundDecision
    with pytest.raises(ValidationError):
        RefundDecision(
            approved=True,
            amount_inr=249,
            reason="valid reason",
            unauthorized_key="bypass",  # type: ignore[call-arg]
        )


def test_invalid_category_fails():
    """Verify an invalid category raises ValidationError."""
    with pytest.raises(ValidationError):
        TriageResponse(
            ticket_id="T-1001",
            category="NOT_A_REAL_CATEGORY",  # type: ignore[arg-type]
            severity=SeverityLevel.P1_HIGH,
            refund=RefundDecision(approved=False, amount_inr=0, reason="No refund"),
            reply_draft="Hello",
            needs_human=False,
            confidence=0.9,
        )


def test_negative_refund_amount_fails():
    """Verify negative refund amounts are rejected."""
    with pytest.raises(ValidationError):
        RefundDecision(
            approved=True,
            amount_inr=-500,
            reason="Invalid negative amount",
        )


def test_confidence_range_validation():
    """Verify confidence must be between 0.0 and 1.0."""
    with pytest.raises(ValidationError):
        TriageResponse(
            ticket_id="T-1001",
            category=TriageCategory.BUG_REPORT,
            severity=SeverityLevel.P2_MEDIUM,
            refund=RefundDecision(approved=False, amount_inr=0, reason="None"),
            reply_draft="Thanks",
            needs_human=True,
            confidence=1.5,  # Out of range
        )

    with pytest.raises(ValidationError):
        TriageResponse(
            ticket_id="T-1001",
            category=TriageCategory.BUG_REPORT,
            severity=SeverityLevel.P2_MEDIUM,
            refund=RefundDecision(approved=False, amount_inr=0, reason="None"),
            reply_draft="Thanks",
            needs_human=True,
            confidence=-0.1,  # Out of range
        )


def test_llm_draft_cannot_decide_refund():
    """Verify LLMTriageDraft does not expose approved or amount_inr fields."""
    assert not hasattr(LLMTriageDraft, "approved")
    assert not hasattr(LLMTriageDraft, "amount_inr")

    draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We will review your refund request.",
        needs_human=False,
        confidence=0.95,
        prompt_injection_detected=False,
        reasoning="User explicitly asked for trial charge refund.",
    )
    assert draft.user_wants_refund is True
    assert draft.category == TriageCategory.REFUND_REQUEST


# -----------------------------------------------------------------------------
# 3. Configuration & Defaults Tests
# -----------------------------------------------------------------------------

def test_config_defaults():
    """Verify configuration defaults without API keys."""
    cfg = Settings(
        GEMINI_API_KEY=None,
        OPENAI_API_KEY=None,
    )
    assert cfg.TRIAGE_MODE == "replay"
    assert cfg.DB_PATH == "triage_state.db"
    assert cfg.CONFIDENCE_THRESHOLD == 0.75


# -----------------------------------------------------------------------------
# 4. PII Redaction & Structured Logging Tests
# -----------------------------------------------------------------------------

def test_t1010_gstin_and_company_redaction():
    """
    Test that logging the text of Ticket T-1010:
    'please share gst invoice for my annual payment, need it for reimbursement. company name and gstin below.
    Acme Interiors, 29ABCDE1234F1Z5'
    redacts both the GSTIN and company name in the captured log output.
    """
    # Create an in-memory stream logger with PIIScrubFilter and JSONLogFormatter
    log_stream = io.StringIO()
    test_logger = logging.getLogger("test_pii_logger")
    test_logger.setLevel(logging.INFO)
    test_logger.handlers.clear()

    handler = logging.StreamHandler(log_stream)
    handler.addFilter(PIIScrubFilter())
    handler.setFormatter(JSONLogFormatter())
    test_logger.addHandler(handler)
    test_logger.propagate = False

    t1010_text = (
        "please share gst invoice for my annual payment, need it for reimbursement. "
        "company name and gstin below.\nAcme Interiors, 29ABCDE1234F1Z5"
    )

    test_logger.info("Processing ticket payload: %s", t1010_text)

    log_output = log_stream.getvalue()
    parsed_log = json.loads(log_output.strip())

    # Raw identifiers must NOT appear
    assert "29ABCDE1234F1Z5" not in log_output
    assert "Acme Interiors" not in log_output

    # Redaction placeholders must appear
    assert "[REDACTED_GSTIN]" in parsed_log["message"]
    assert "[REDACTED_ENTITY]" in parsed_log["message"]


def test_email_and_upi_redaction():
    """Verify email addresses and UPI virtual payment addresses are redacted."""
    sample = "Reach me at customer.care@gmail.com or refund to 9876543210@okhdfcbank"
    redacted = scrub_pii(sample)
    assert "customer.care@gmail.com" not in redacted
    assert "9876543210@okhdfcbank" not in redacted
    assert "[REDACTED_EMAIL_UPI]" in redacted


def test_phone_and_card_redaction():
    """Verify 10-16 digit phone numbers and card numbers are redacted."""
    sample = "Call +91 9876543210 or card 4111 2222 3333 4444"
    redacted = scrub_pii(sample)
    assert "9876543210" not in redacted
    assert "4111 2222 3333 4444" not in redacted
    assert "[REDACTED_NUMBER]" in redacted


def test_log_event_forbids_raw_body_and_subject():
    """Verify log_event raises ValueError when body or subject is passed."""
    with pytest.raises(ValueError, match="forbidden in log events"):
        log_event(
            event_type="ticket_received",
            ticket_id="T-1001",
            body="i only paid 1 rupee to try the app. refund it.",
        )

    with pytest.raises(ValueError, match="forbidden in log events"):
        log_event(
            event_type="ticket_received",
            ticket_id="T-1001",
            subject="charged 249 without telling me",
        )


def test_log_event_valid_metadata():
    """Verify log_event emits valid structured JSON for safe metadata."""
    log_stream = io.StringIO()
    test_logger = setup_logger("dhaba")
    
    # Temporarily capture output
    handler = logging.StreamHandler(log_stream)
    handler.addFilter(PIIScrubFilter())
    handler.setFormatter(JSONLogFormatter())
    test_logger.addHandler(handler)

    try:
        log_event(
            event_type="triage_completed",
            ticket_id="T-1001",
            category="REFUND_REQUEST",
            severity="P1_HIGH",
            refund_approved=True,
            refund_amount=249,
        )
        output = log_stream.getvalue().strip()
        record = json.loads(output)
        assert record["event_type"] == "triage_completed"
        assert record["ticket_id"] == "T-1001"
        assert record["refund_approved"] is True
        assert record["refund_amount"] == 249
    finally:
        test_logger.removeHandler(handler)

