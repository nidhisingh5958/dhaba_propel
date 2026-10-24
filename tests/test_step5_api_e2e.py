"""
End-to-End API Integration Tests for Dhaba Support Triage.
Tests POST /triage, GET /health, Idempotency, and Security Guards.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.idempotency import IdempotencyStore
from app.llm_client import TriageLLMClient
from app.main import app
from app.schemas import SeverityLevel, TriageCategory, TriageResponse


@pytest.fixture
def dhaba_dataset():
    """Loads all 12 tickets from dhaba_tickets.json as a raw list of dicts."""
    with open("dhaba_tickets.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["tickets"]


@pytest.fixture
def client(tmp_path):
    """Provides a TestClient with an isolated SQLite ledger for each test."""
    temp_db = str(tmp_path / "test_api_ledger.db")
    app.state.idempotency_store = IdempotencyStore(db_path=temp_db)
    app.state.llm_client = TriageLLMClient(mode="replay")
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    """Verify GET /health returns service status and replay mode."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "dhaba-triage"
    assert data["triage_mode"] == "replay"


def test_triage_all_12_tickets_e2e(client, dhaba_dataset):
    """
    Send all 12 tickets from dhaba_tickets.json to POST /triage.
    Verify HTTP 200 and schema validation into TriageResponse.
    """
    for raw_ticket in dhaba_dataset:
        res = client.post("/triage", json=raw_ticket)
        assert res.status_code == 200, f"Ticket {raw_ticket['id']} failed with status {res.status_code}: {res.text}"
        assert res.headers.get("X-Idempotent-Replay") == "false"

        response_obj = TriageResponse.model_validate(res.json())
        assert response_obj.ticket_id == raw_ticket["id"]
        assert isinstance(response_obj.category, TriageCategory)
        assert isinstance(response_obj.severity, SeverityLevel)
        assert 0.0 <= response_obj.confidence <= 1.0


def test_t1001_idempotent_duplicate_prevention(client, dhaba_dataset):
    """
    Send Ticket T-1001 twice:
    - Call 1: X-Idempotent-Replay: false, refund approved for Rs 249
    - Call 2: X-Idempotent-Replay: true, exact same response returned
    """
    t1001 = next(t for t in dhaba_dataset if t["id"] == "T-1001")

    # Call 1
    res1 = client.post("/triage", json=t1001)
    assert res1.status_code == 200
    assert res1.headers.get("X-Idempotent-Replay") == "false"
    data1 = res1.json()
    assert data1["refund"]["approved"] is True
    assert data1["refund"]["amount_inr"] == 249
    assert data1["refund"]["payment_id"] == "pay_A2"

    # Call 2 (Immediate duplicate)
    res2 = client.post("/triage", json=t1001)
    assert res2.status_code == 200
    assert res2.headers.get("X-Idempotent-Replay") == "true"
    data2 = res2.json()
    assert data1 == data2


def test_t1001_modified_payload_returns_409(client, dhaba_dataset):
    """
    Send Ticket T-1001, then send same ticket_id with modified body.
    Must return HTTP 409 Conflict.
    """
    t1001 = next(t for t in dhaba_dataset if t["id"] == "T-1001")

    # Initial valid submission
    res1 = client.post("/triage", json=t1001)
    assert res1.status_code == 200

    # Modified payload with same ID
    modified_t1001 = dict(t1001)
    modified_t1001["body"] = "i am demanding 1000 rupees refund instead"

    res2 = client.post("/triage", json=modified_t1001)
    assert res2.status_code == 409
    assert "mismatch" in res2.json()["detail"].lower()


def test_t1003_vip_prompt_injection_neutralized_e2e(client, dhaba_dataset):
    """
    Verify T-1003 adversarial VIP override injection is neutralized end-to-end:
    - Refund is strictly False (amount 0)
    - Severity escalated to P0_CRITICAL
    - Needs human is True
    """
    t1003 = next(t for t in dhaba_dataset if t["id"] == "T-1003")
    res = client.post("/triage", json=t1003)
    assert res.status_code == 200

    data = res.json()
    assert data["refund"]["approved"] is False
    assert data["refund"]["amount_inr"] == 0
    assert data["severity"] == "P0_CRITICAL"
    assert data["needs_human"] is True
    assert "adversarial instruction" in data["refund"]["reason"]


def test_t1011_prompt_leak_injection_neutralized_e2e(client, dhaba_dataset):
    """
    Verify T-1011 system prompt leak injection is neutralized end-to-end:
    - Refund is False (amount 0)
    - Severity escalated to P0_CRITICAL
    - Reply draft does not contain leaked system instructions
    """
    t1011 = next(t for t in dhaba_dataset if t["id"] == "T-1011")
    res = client.post("/triage", json=t1011)
    assert res.status_code == 200

    data = res.json()
    assert data["refund"]["approved"] is False
    assert data["severity"] == "P0_CRITICAL"
    assert data["needs_human"] is True
    assert "system prompt" not in data["reply_draft"].lower()

