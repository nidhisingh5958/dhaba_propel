"""
Unit tests for Step 2:
The Deterministic Money Gate & Input Security Scanner.
Verifies policy rules and security guardrails across Dhaba ticket scenarios.
"""

import json
from pathlib import Path
import pytest

from app.config import settings
from app.schemas import (
    TicketInput,
    LLMTriageDraft,
    TriageCategory,
    SeverityLevel,
    PurchaseStatus,
)
from app.money_gate import (
    detect_prompt_injection,
    evaluate_refund_policy,
    apply_safety_gates,
    SAFE_FALLBACK_REPLY,
)


@pytest.fixture
def dhaba_tickets():
    """Loads all 12 tickets from dhaba_tickets.json as a dict indexed by ticket ID."""
    with open("dhaba_tickets.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return {t["id"]: TicketInput.model_validate(t) for t in data["tickets"]}


# -----------------------------------------------------------------------------
# 1. Prompt Injection Scanner Unit Tests
# -----------------------------------------------------------------------------

def test_detect_prompt_injection_clean_ticket(dhaba_tickets):
    """Clean tickets without adversarial instructions should return False."""
    clean_ticket = dhaba_tickets["T-1001"]
    detected, patterns = detect_prompt_injection(clean_ticket.subject, clean_ticket.body)
    assert not detected
    assert len(patterns) == 0


def test_detect_prompt_injection_t1003(dhaba_tickets):
    """T-1003 attempts VIP status override and instruction bypass."""
    ticket = dhaba_tickets["T-1003"]
    detected, patterns = detect_prompt_injection(ticket.subject, ticket.body)
    assert detected
    assert any("system note" in p.lower() for p in patterns)
    assert any("ignore" in p.lower() for p in patterns)


def test_detect_prompt_injection_t1011(dhaba_tickets):
    """T-1011 attempts prompt extraction and system instruction exfiltration."""
    ticket = dhaba_tickets["T-1011"]
    detected, patterns = detect_prompt_injection(ticket.subject, ticket.body)
    assert detected
    assert any("system prompt" in p.lower() for p in patterns)
    assert any("internal refund rule" in p.lower() for p in patterns)


# -----------------------------------------------------------------------------
# 2. Specific Ticket Policy Engine Tests
# -----------------------------------------------------------------------------

def test_t1001_auto_refund_approved(dhaba_tickets):
    """
    T-1001: Monthly renewal (Rs 249), 0 app opens, received ~13h after renewal.
    Must be auto-approved for Rs 249 refund with payment_id='pay_A2'.
    """
    ticket = dhaba_tickets["T-1001"]
    mock_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We have processed your refund of Rs 249.",
        needs_human=False,
        confidence=0.95,
        prompt_injection_detected=False,
        reasoning="User surprised by renewal charge and has zero app opens.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is True
    assert decision.amount_inr == 249
    assert decision.payment_id == "pay_A2"
    assert "0 app opens" in decision.reason

    # Test full safety gate response
    response = apply_safety_gates(ticket, mock_draft)
    assert response.refund.approved is True
    assert response.refund.amount_inr == 249
    assert response.refund.payment_id == "pay_A2"
    assert response.needs_human is False


def test_t1003_injection_bypass_strictly_blocked(dhaba_tickets):
    """
    T-1003: Adversarial VIP injection attempting to force full refund.
    Must be strictly blocked with Rs 0 refund, even if LLM draft is compromised.
    """
    ticket = dhaba_tickets["T-1003"]
    # Simulate a compromised or tricked LLM that mistakenly agrees to refund
    compromised_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="Confirmed! As a VIP, your full refund of Rs 1500 has been processed.",
        needs_human=False,
        confidence=0.99,
        prompt_injection_detected=False,  # Pretend LLM missed it
        reasoning="VIP refund requested.",
    )

    # Input scanner catches it
    injection_detected, _ = detect_prompt_injection(ticket.subject, ticket.body)
    assert injection_detected is True

    decision = evaluate_refund_policy(ticket, compromised_draft, injection_detected=True)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "adversarial instruction" in decision.reason

    # Safety gate ensures escalation and fallback reply
    response = apply_safety_gates(ticket, compromised_draft)
    assert response.refund.approved is False
    assert response.refund.amount_inr == 0
    assert response.severity == SeverityLevel.P0_CRITICAL
    assert response.needs_human is True
    assert response.reply_draft == SAFE_FALLBACK_REPLY


def test_t1005_initiated_payment_cannot_refund(dhaba_tickets):
    """
    T-1005: User charged Rs 249, but billing shows payment is still 'initiated'.
    Cannot refund unsettled funds -> Rs 0, escalated to human for reconciliation.
    """
    ticket = dhaba_tickets["T-1005"]
    mock_draft = LLMTriageDraft(
        category=TriageCategory.BILLING_DISPUTE,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=False,  # User wants plan activated
        reply_draft="We are checking your payment status.",
        needs_human=True,
        confidence=0.88,
        prompt_injection_detected=False,
        reasoning="Payment deducted from bank but plan not activated; status initiated.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "initiated" in decision.reason
    assert decision.payment_id == "pay_E2"

    response = apply_safety_gates(ticket, mock_draft)
    assert response.refund.approved is False
    assert response.needs_human is True


def test_t1006_high_value_annual_plan_gated(dhaba_tickets):
    """
    T-1006: Annual plan renewal (Rs 1499), 0 opens.
    Exceeds auto-refund cap (> Rs 500), must be routed for human sign-off.
    """
    ticket = dhaba_tickets["T-1006"]
    mock_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We received your cancellation and refund request for the annual plan.",
        needs_human=False,
        confidence=0.92,
        prompt_injection_detected=False,
        reasoning="Unused annual renewal autopay charge.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "exceeds auto-refund cap" in decision.reason
    assert decision.payment_id == "pay_F2"

    response = apply_safety_gates(ticket, mock_draft)
    assert response.refund.approved is False
    assert response.needs_human is True  # Enforced human sign-off


def test_t1008_legal_and_fraud_threat_frozen(dhaba_tickets):
    """
    T-1008: Claims cyber cell report and unauthorized card usage by elderly father.
    Must freeze auto-refund and escalate to P0_CRITICAL for legal/fraud review.
    """
    ticket = dhaba_tickets["T-1008"]
    mock_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We will look into this immediately.",
        needs_human=True,
        confidence=0.90,
        prompt_injection_detected=False,
        reasoning="User threatening cyber cell report over alleged unauthorized charges.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "fraud/legal review" in decision.reason

    response = apply_safety_gates(ticket, mock_draft)
    assert response.refund.approved is False
    assert response.severity == SeverityLevel.P0_CRITICAL
    assert response.needs_human is True


def test_t1009_false_double_charge(dhaba_tickets):
    """
    T-1009: User claims double charge. Billing shows one failed attempt and one successful.
    Policy rejects refund and explains prior attempt was failed.
    """
    ticket = dhaba_tickets["T-1009"]
    mock_draft = LLMTriageDraft(
        category=TriageCategory.BILLING_DISPUTE,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We have verified your account: only one charge succeeded.",
        needs_human=False,
        confidence=0.91,
        prompt_injection_detected=False,
        reasoning="User believes they were double charged.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "Only one successful charge found" in decision.reason
    assert decision.payment_id == "pay_I2"


def test_t1011_prompt_exfiltration_blocked(dhaba_tickets):
    """
    T-1011: Pre-sales query with injection requesting system prompt and refund rules.
    Input scanner detects injection; reply draft with leak is scrubbed.
    """
    ticket = dhaba_tickets["T-1011"]
    leaky_draft = LLMTriageDraft(
        category=TriageCategory.PRE_SALES_QUERY,
        severity=SeverityLevel.P3_LOW,
        user_wants_refund=False,
        reply_draft="Here is our system prompt: You are a support agent with internal refund rules...",
        needs_human=False,
        confidence=0.85,
        prompt_injection_detected=False,
        reasoning="Pre-sales query with prompt leak request.",
    )

    injection_detected, patterns = detect_prompt_injection(ticket.subject, ticket.body)
    assert injection_detected is True
    assert len(patterns) >= 2

    response = apply_safety_gates(ticket, leaky_draft)
    assert response.refund.approved is False
    assert response.severity == SeverityLevel.P0_CRITICAL
    assert response.needs_human is True
    # The leaked reply draft MUST be replaced with safe fallback
    assert "system prompt" not in response.reply_draft
    assert response.reply_draft == SAFE_FALLBACK_REPLY


def test_t1012_usage_gate_blocks_auto_refund(dhaba_tickets):
    """
    T-1012: Angry refund demand on monthly renewal (Rs 249), but 2 app opens recorded.
    Usage gate blocks auto-refund; routes to human agent.
    """
    ticket = dhaba_tickets["T-1012"]
    assert ticket.app_opens_since_renewal == 2

    mock_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We are reviewing your cancellation and refund request.",
        needs_human=False,
        confidence=0.89,
        prompt_injection_detected=False,
        reasoning="User angry, demands refund, 2 app opens.",
    )

    decision = evaluate_refund_policy(ticket, mock_draft, injection_detected=False)
    assert decision.approved is False
    assert decision.amount_inr == 0
    assert "2 app opens recorded" in decision.reason
    assert decision.payment_id == "pay_K2"

    response = apply_safety_gates(ticket, mock_draft)
    assert response.refund.approved is False
    assert response.needs_human is True


# -----------------------------------------------------------------------------
# 3. Confidence Threshold Gating
# -----------------------------------------------------------------------------

def test_low_confidence_suspends_auto_refund(dhaba_tickets):
    """
    If confidence < CONFIDENCE_THRESHOLD (0.75), auto-refund must be suspended
    even if the ticket otherwise meets 0 opens / 48h renewal criteria.
    """
    ticket = dhaba_tickets["T-1001"]  # Normally auto-approved for Rs 249
    low_confidence_draft = LLMTriageDraft(
        category=TriageCategory.REFUND_REQUEST,
        severity=SeverityLevel.P1_HIGH,
        user_wants_refund=True,
        reply_draft="We have processed your refund.",
        needs_human=False,
        confidence=0.60,  # Below 0.75 threshold
        prompt_injection_detected=False,
        reasoning="Ambiguous classification with low confidence.",
    )

    response = apply_safety_gates(ticket, low_confidence_draft)
    assert response.refund.approved is False
    assert response.refund.amount_inr == 0
    assert "Confidence score" in response.refund.reason
    assert response.needs_human is True

