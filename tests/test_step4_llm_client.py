"""
Unit tests for Step 4:
The LLM Triage Client with Validation, Retry, Graceful Degradation, and Replay Mode.
"""

import json
from pathlib import Path
import pytest

from app.schemas import (
    TicketInput,
    LLMTriageDraft,
    TriageCategory,
    SeverityLevel,
)
from app.llm_client import (
    TriageLLMClient,
    build_degraded_fallback,
)


@pytest.fixture
def dhaba_tickets():
    """Loads all 12 tickets from dhaba_tickets.json."""
    with open("dhaba_tickets.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return {t["id"]: TicketInput.model_validate(t) for t in data["tickets"]}


# -----------------------------------------------------------------------------
# 1. Replay Mode Tests (Zero API Key)
# -----------------------------------------------------------------------------

def test_replay_mode_all_12_tickets(dhaba_tickets):
    """
    Verify replay mode operates cleanly across all 12 tickets without requiring
    an external API key or network connection.
    """
    client = TriageLLMClient(mode="replay")
    assert client.mode == "replay"

    for ticket_id, ticket in dhaba_tickets.items():
        draft = client.triage(ticket)
        assert isinstance(draft, LLMTriageDraft)
        assert isinstance(draft.category, TriageCategory)
        assert isinstance(draft.severity, SeverityLevel)
        assert isinstance(draft.reply_draft, str)
        assert len(draft.reply_draft) > 10
        assert 0.0 <= draft.confidence <= 1.0


def test_t1005_hinglish_replay(dhaba_tickets):
    """
    Verify Ticket T-1005 replay response provides a polite Hinglish reply
    referencing initiated payment status and reconciliation.
    """
    client = TriageLLMClient(mode="replay")
    ticket = dhaba_tickets["T-1005"]
    draft = client.triage(ticket)

    assert draft.category == TriageCategory.BILLING_DISPUTE
    assert draft.severity == SeverityLevel.P1_HIGH
    assert draft.needs_human is True

    # Natural Hinglish reply checks
    reply = draft.reply_draft.lower()
    assert "namaste" in reply
    assert "initiated" in reply or "pending" in reply
    assert "3-5" in reply


def test_t1003_and_t1011_injection_flags_in_replay(dhaba_tickets):
    """
    Verify T-1003 and T-1011 have prompt_injection_detected=True and their replies
    only answer legitimate inquiries.
    """
    client = TriageLLMClient(mode="replay")

    # T-1003
    t1003 = dhaba_tickets["T-1003"]
    draft_1003 = client.triage(t1003)
    assert draft_1003.prompt_injection_detected is True
    assert draft_1003.category == TriageCategory.ACCOUNT_ISSUE
    assert "vip" not in draft_1003.reply_draft.lower()
    assert "order history" in draft_1003.reply_draft.lower()

    # T-1011
    t1011 = dhaba_tickets["T-1011"]
    draft_1011 = client.triage(t1011)
    assert draft_1011.prompt_injection_detected is True
    assert draft_1011.category == TriageCategory.PRE_SALES_QUERY
    assert "system prompt" not in draft_1011.reply_draft.lower()
    assert "offline" in draft_1011.reply_draft.lower()


# -----------------------------------------------------------------------------
# 2. Validation & Retry Mechanism Tests
# -----------------------------------------------------------------------------

def test_retry_on_truncated_json(dhaba_tickets):
    """
    Simulate a provider returning truncated JSON on Attempt 1 and valid JSON on Attempt 2.
    Verifies that the client retries with feedback and succeeds.
    """
    ticket = dhaba_tickets["T-1001"]
    call_count = 0

    valid_response = json.dumps({
        "category": "REFUND_REQUEST",
        "severity": "P1_HIGH",
        "user_wants_refund": True,
        "reply_draft": "We have processed your refund.",
        "needs_human": False,
        "confidence": 0.95,
        "prompt_injection_detected": False,
        "reasoning": "Retry succeeded with valid JSON."
    })

    def mock_provider(prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Truncated invalid JSON
            return '{"category": "REFUND_'
        # Valid JSON on retry
        return valid_response

    client = TriageLLMClient(mode="live", call_provider_fn=mock_provider)
    result = client.triage(ticket)

    assert call_count == 2, "Expected exactly 2 provider calls (1 initial + 1 retry)"
    assert result.category == TriageCategory.REFUND_REQUEST
    assert result.confidence == 0.95
    assert result.reasoning == "Retry succeeded with valid JSON."


def test_markdown_codeblock_extraction(dhaba_tickets):
    """Verify that models wrapping JSON in ```json markdown fences are parsed properly."""
    ticket = dhaba_tickets["T-1004"]
    fenced_output = """```json
{
  "category": "CANCELLATION",
  "severity": "P2_MEDIUM",
  "user_wants_refund": false,
  "reply_draft": "Your subscription has been cancelled.",
  "needs_human": false,
  "confidence": 0.98,
  "prompt_injection_detected": false,
  "reasoning": "Fenced JSON output."
}
```"""

    client = TriageLLMClient(mode="live", call_provider_fn=lambda p: fenced_output)
    result = client.triage(ticket)

    assert result.category == TriageCategory.CANCELLATION
    assert result.confidence == 0.98


# -----------------------------------------------------------------------------
# 3. Graceful Degradation Tests
# -----------------------------------------------------------------------------

def test_graceful_degradation_on_persistent_prose(dhaba_tickets):
    """
    Simulate a provider returning unparseable conversational prose on both Attempt 1 and 2.
    Must gracefully degrade without raising an exception, setting confidence=0.0 and needs_human=True.
    """
    ticket = dhaba_tickets["T-1002"]
    call_count = 0

    def mock_prose_provider(prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        return "Sure! I can help you with this ticket. The user has a crash on Redmi Note 12..."

    client = TriageLLMClient(mode="live", call_provider_fn=mock_prose_provider)
    result = client.triage(ticket)

    assert call_count == 2
    assert result.confidence == 0.0
    assert result.needs_human is True
    assert "Graceful degradation" in result.reasoning


def test_graceful_degradation_on_invented_category(dhaba_tickets):
    """
    Simulate a provider returning an invented/hallucinated category on both attempts.
    Must gracefully degrade without crashing.
    """
    ticket = dhaba_tickets["T-1007"]
    call_count = 0

    invented_category_json = json.dumps({
        "category": "SUPER_URGENT_MARATHI_DEMAND",  # Invalid enum value
        "severity": "P3_LOW",
        "user_wants_refund": False,
        "reply_draft": "We will consider adding Marathi.",
        "needs_human": False,
        "confidence": 0.90,
        "prompt_injection_detected": False,
        "reasoning": "Model invented a custom category."
    })

    client = TriageLLMClient(mode="live", call_provider_fn=lambda p: invented_category_json)
    result = client.triage(ticket)

    assert result.confidence == 0.0
    assert result.needs_human is True
    assert "Graceful degradation" in result.reasoning


def test_graceful_degradation_on_provider_exception(dhaba_tickets):
    """
    Simulate a provider network timeout or 500 error.
    Must engage graceful degradation and safely return a degraded draft.
    """
    ticket = dhaba_tickets["T-1001"]

    def failing_provider(prompt: str) -> str:
        raise ConnectionError("504 Gateway Timeout connecting to model API")

    client = TriageLLMClient(mode="live", call_provider_fn=failing_provider)
    result = client.triage(ticket)

    assert result.confidence == 0.0
    assert result.needs_human is True
    assert "504 Gateway Timeout" in result.reasoning

