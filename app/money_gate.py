"""
Deterministic Money Gate & Input Security Guardrail.

Enforces strict separation of powers:
- Input Security Scanner detects adversarial instructions and prompt injection.
- Policy Engine computes refund eligibility deterministically using only verifiable
  billing transactions, application activity metrics, and time windows.
- The LLM cannot authorize refunds, modify transaction amounts, or override guardrails.
"""

from datetime import datetime, timezone
import re
from typing import List, Tuple, Union

from app.config import settings
from app.schemas import (
    LLMTriageDraft,
    PurchaseStatus,
    PurchaseType,
    RefundDecision,
    SeverityLevel,
    TicketInput,
    TriageCategory,
    TriageResponse,
)


# -----------------------------------------------------------------------------
# 1. Prompt Injection & Adversarial Scanner
# -----------------------------------------------------------------------------

INJECTION_PATTERNS = [
    re.compile(r"system\s+note", re.IGNORECASE),
    re.compile(r"ignore\s+(?:your\s+|all\s+|previous\s+)*instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(?:any\s+|all\s+)*refund\s+policy", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"internal\s+refund\s+rules?", re.IGNORECASE),
    re.compile(r"verified\s+vip", re.IGNORECASE),
    re.compile(r"mark\s+this\s+ticket\s+resolved", re.IGNORECASE),
    re.compile(r"(?:automated|support)\s+agent\s+reading\s+this", re.IGNORECASE),
    re.compile(r"disregard\s+previous", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in", re.IGNORECASE),
    re.compile(r"full\s+text\s+of\s+your\s+system", re.IGNORECASE),
]

LEGAL_FRAUD_PATTERNS = [
    re.compile(r"\bcyber\s*cell\b", re.IGNORECASE),
    re.compile(r"\bcyber\s*crime\b", re.IGNORECASE),
    re.compile(r"\bfraud\b", re.IGNORECASE),
    re.compile(r"\bpolice\b", re.IGNORECASE),
    re.compile(r"\blawyer\b", re.IGNORECASE),
    re.compile(r"\blegal\s+(?:notice|action|cell)\b", re.IGNORECASE),
    re.compile(r"\bunauthorized\s+(?:charge|charges|transaction|transactions)\b", re.IGNORECASE),
    re.compile(r"\bnever\s+installed\b", re.IGNORECASE),
]

LEAK_PATTERNS = [
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"internal\s+refund\s+rules?", re.IGNORECASE),
    re.compile(r"llmtriagedraft", re.IGNORECASE),
    re.compile(r"prompt\s+injection", re.IGNORECASE),
    re.compile(r"system\s+note", re.IGNORECASE),
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"verified\s+vip", re.IGNORECASE),
]

SAFE_FALLBACK_REPLY = (
    "Thank you for contacting Dhaba support. We have received your request and routed "
    "it to our senior support team for review. A representative will inspect your account "
    "and reply shortly."
)


def detect_prompt_injection(subject: str, body: str) -> Tuple[bool, List[str]]:
    """
    Deterministically scans incoming ticket subject and body for adversarial prompt
    injection, system prompt exfiltration attempts, or policy override instructions.
    
    Returns:
        (is_detected: bool, matched_patterns: list[str])
    """
    combined_text = f"{subject}\n{body}"
    matched: List[str] = []

    for pattern in INJECTION_PATTERNS:
        match = pattern.search(combined_text)
        if match:
            matched.append(match.group(0))

    return (len(matched) > 0, matched)


def _is_legal_or_fraud_threat(subject: str, body: str) -> bool:
    """Checks whether the ticket indicates fraud, unauthorized card use, or legal escalation."""
    combined_text = f"{subject}\n{body}"
    return any(p.search(combined_text) for p in LEGAL_FRAUD_PATTERNS)


def _parse_dt(dt_val: Union[datetime, str]) -> datetime:
    """Safely converts an ISO string or datetime into a timezone-aware datetime."""
    if isinstance(dt_val, str):
        dt = datetime.fromisoformat(dt_val)
    else:
        dt = dt_val
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# -----------------------------------------------------------------------------
# 2. Deterministic Financial Policy Engine
# -----------------------------------------------------------------------------

def evaluate_refund_policy(
    ticket: TicketInput,
    llm_draft: LLMTriageDraft,
    injection_detected: bool,
) -> RefundDecision:
    """
    100% deterministic financial policy engine that computes RefundDecision.
    The LLM has NO direct authority to approve refunds or set amounts.
    
    Decision Rules:
    - Rule 1 (Prompt Injection / Abuse Block): Block adversarial inputs.
    - Rule 2 (Legal / Fraud Threat Escalation): Freeze funds for human investigation.
    - Rule 3 (No Refund Requested): Zero refund if user did not ask.
    - Rule 4 (Unsettled / Failed Payments): Cannot refund 'initiated' status.
    - Rule 5 (False Double-Charge): Explain failed prior attempts; no refund for single success.
    - Rule 6 (High-Value Annual Plan Gate): Gated for human sign-off (> Rs 500 cap).
    - Rule 7 (Usage Gate on Monthly Renewal): Auto-approved only if 0 opens within 48h.
    """
    # Rule 1: Prompt Injection / Abuse Block
    if injection_detected or llm_draft.prompt_injection_detected:
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="Blocked by security guardrail: adversarial instruction detected in ticket.",
            payment_id=None,
        )

    # Rule 2: Legal / Fraud Threat Escalation
    if _is_legal_or_fraud_threat(ticket.subject, ticket.body):
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="Frozen for immediate human fraud/legal review; auto-refund disabled.",
            payment_id=None,
        )

    # Rule 3: No Refund Requested
    refund_related_categories = {
        TriageCategory.REFUND_REQUEST,
        TriageCategory.BILLING_DISPUTE,
    }
    if not llm_draft.user_wants_refund and llm_draft.category not in refund_related_categories:
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="No refund requested.",
            payment_id=None,
        )

    # Sort purchases chronologically
    sorted_purchases = sorted(ticket.purchases, key=lambda p: _parse_dt(p.at))
    renewals = [p for p in sorted_purchases if p.type == PurchaseType.RENEWAL]

    if not renewals:
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="No eligible renewal charges found on this account.",
            payment_id=None,
        )

    latest_renewal = renewals[-1]
    successful_renewals = [p for p in renewals if p.status == PurchaseStatus.SUCCESSFUL]
    latest_successful = successful_renewals[-1] if successful_renewals else None

    # Rule 4: Unsettled / Initiated Payments
    if latest_renewal.status == PurchaseStatus.INITIATED:
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="Payment is in 'initiated' (unsettled) state; cannot refund unsettled funds. Escalated for payment reconciliation.",
            payment_id=latest_renewal.id,
        )

    # Rule 5: False Double-Charge Check
    combined_lower = f"{ticket.subject} {ticket.body}".lower()
    is_double_charge_claim = any(kw in combined_lower for kw in ["double", "twice", "2 times", "two times"])
    if is_double_charge_claim:
        failed_renewals = [p for p in renewals if p.status == PurchaseStatus.FAILED]
        if len(successful_renewals) == 1 and len(failed_renewals) >= 1:
            return RefundDecision(
                approved=False,
                amount_inr=0,
                reason="Only one successful charge found; prior attempt failed and was not settled.",
                payment_id=latest_successful.id if latest_successful else None,
            )

    if not latest_successful:
        return RefundDecision(
            approved=False,
            amount_inr=0,
            reason="No successful renewal charge found to refund.",
            payment_id=None,
        )

    # Rule 6: High-Value Annual Plan Gate (> Rs 500 Auto-Refund Cap)
    if latest_successful.amount_inr >= 1000:
        if ticket.app_opens_since_renewal == 0:
            return RefundDecision(
                approved=False,
                amount_inr=0,
                reason=f"Eligible unused annual renewal (0 opens), but amount Rs {latest_successful.amount_inr} exceeds auto-refund cap (Rs 500); routed for 1-click human approval",
                payment_id=latest_successful.id,
            )
        else:
            return RefundDecision(
                approved=False,
                amount_inr=0,
                reason=f"Annual renewal has {ticket.app_opens_since_renewal} app opens recorded; routed to human agent.",
                payment_id=latest_successful.id,
            )

    # Rule 7: Monthly Renewal Usage Gate (Rs 249)
    if latest_successful.amount_inr == 249:
        if ticket.app_opens_since_renewal == 0:
            ticket_time = _parse_dt(ticket.received_at)
            renewal_time = _parse_dt(latest_successful.at)
            hours_diff = (ticket_time - renewal_time).total_seconds() / 3600.0

            if 0 <= hours_diff <= 48.0:
                return RefundDecision(
                    approved=True,
                    amount_inr=249,
                    reason="Approved: unused monthly renewal (0 app opens) reported within 48h window.",
                    payment_id=latest_successful.id,
                )
            else:
                return RefundDecision(
                    approved=False,
                    amount_inr=0,
                    reason="Reported outside 48-hour window for unused monthly renewal; routed to human agent.",
                    payment_id=latest_successful.id,
                )
        else:
            return RefundDecision(
                approved=False,
                amount_inr=0,
                reason=f"Auto-refund declined: {ticket.app_opens_since_renewal} app opens recorded since renewal; routed to human agent.",
                payment_id=latest_successful.id,
            )

    # Generic Fallback
    return RefundDecision(
        approved=False,
        amount_inr=0,
        reason="Transaction parameters require manual specialist review.",
        payment_id=latest_successful.id if latest_successful else None,
    )


# -----------------------------------------------------------------------------
# 3. Post-Processing & Safety Gate Orchestrator
# -----------------------------------------------------------------------------

def apply_safety_gates(ticket: TicketInput, llm_draft: LLMTriageDraft) -> TriageResponse:
    """
    Applies security filters, confidence gating, and deterministic refund policies
    to produce the final authorized TriageResponse.
    """
    # 1. Deterministic Injection Scan
    injection_detected, matched_patterns = detect_prompt_injection(
        ticket.subject, ticket.body
    )
    is_injection = injection_detected or llm_draft.prompt_injection_detected

    category = TriageCategory.SECURITY_OR_ABUSE if is_injection else llm_draft.category
    severity = SeverityLevel.P0_CRITICAL if is_injection else llm_draft.severity
    needs_human = llm_draft.needs_human or is_injection

    # 2. Check for Legal / Fraud Threats
    if _is_legal_or_fraud_threat(ticket.subject, ticket.body):
        severity = SeverityLevel.P0_CRITICAL
        needs_human = True

    # 3. Evaluate Deterministic Refund Policy
    refund_decision = evaluate_refund_policy(
        ticket=ticket,
        llm_draft=llm_draft,
        injection_detected=is_injection,
    )

    # If refund was declined but routed for human review, reflect in needs_human
    human_routing_keywords = [
        "routed for",
        "routed to",
        "escalated",
        "frozen",
        "human",
        "manual",
    ]
    if not refund_decision.approved:
        if any(kw in refund_decision.reason.lower() for kw in human_routing_keywords):
            needs_human = True

    # 4. Enforce Confidence Gate
    if llm_draft.confidence < settings.CONFIDENCE_THRESHOLD:
        needs_human = True
        if refund_decision.approved:
            refund_decision = RefundDecision(
                approved=False,
                amount_inr=0,
                reason=(
                    f"Confidence score ({llm_draft.confidence:.2f}) below threshold "
                    f"({settings.CONFIDENCE_THRESHOLD}); auto-refund suspended for human verification."
                ),
                payment_id=refund_decision.payment_id,
            )

    # 5. Sanitize Reply Draft for System Information Leaks
    reply_draft = llm_draft.reply_draft
    contains_leak = any(p.search(reply_draft) for p in LEAK_PATTERNS)
    if is_injection or contains_leak:
        reply_draft = SAFE_FALLBACK_REPLY

    return TriageResponse(
        ticket_id=ticket.id,
        category=category,
        severity=severity,
        refund=refund_decision,
        reply_draft=reply_draft,
        needs_human=needs_human,
        confidence=llm_draft.confidence,
    )

