"""
SQLite Idempotency Store for Dhaba Support Triage.

Guarantees strict at-most-once refund execution:
- Concurrent or duplicate ticket arrivals cannot trigger double refunds.
- Re-submissions with the exact same payload return the cached TriageResponse.
- Re-submissions with a modified payload under the same ticket_id raise IdempotencyConflictError (HTTP 409).
"""

from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from typing import Optional, Union

from app.config import settings
from app.logger import log_event
from app.schemas import TicketInput, TriageResponse


class IdempotencyConflictError(Exception):
    """
    Raised when a ticket_id arrives that was previously processed,
    but with a differing payload hash (conflicting payload / replay alteration).
    Mapped to HTTP 409 Conflict at the API boundary.
    """
    pass


def compute_payload_hash(ticket: Union[TicketInput, dict, str]) -> str:
    """
    Computes a canonical SHA-256 hash of the input ticket.
    Key sorting and standard separators ensure strict determinism.
    """
    if isinstance(ticket, TicketInput):
        data = ticket.model_dump(mode="json")
    elif isinstance(ticket, dict):
        data = ticket
    elif isinstance(ticket, str):
        data = json.loads(ticket)
    else:
        raise TypeError(f"Unsupported payload type for hashing: {type(ticket)}")

    canonical_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class IdempotencyStore:
    """
    Atomic SQLite-backed ledger for ticket deduplication and idempotency.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DB_PATH
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes the database schema and WAL mode."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS triage_ledger (
                    ticket_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    refund_approved INTEGER NOT NULL,
                    refund_amount_inr INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_payload_hash ON triage_ledger (payload_hash);"
            )
            conn.commit()

    def get_existing(self, ticket_id: str, payload_hash: str) -> Optional[TriageResponse]:
        """
        Retrieves a previously computed TriageResponse for the given ticket.
        
        Raises:
            IdempotencyConflictError: If ticket_id exists but payload_hash differs.
        
        Returns:
            Cached TriageResponse if exact match, or None if ticket has not been seen.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT payload_hash, response_json FROM triage_ledger WHERE ticket_id = ?",
                (ticket_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            stored_hash = row["payload_hash"]
            if stored_hash != payload_hash:
                raise IdempotencyConflictError(
                    f"Ticket '{ticket_id}' was previously processed with a different payload "
                    f"(hash mismatch: stored={stored_hash[:8]}..., incoming={payload_hash[:8]}...). "
                    "Cannot alter an already processed ticket."
                )

            log_event(
                event_type="idempotency_cache_hit",
                ticket_id=ticket_id,
                payload_hash=payload_hash[:8],
            )
            return TriageResponse.model_validate_json(row["response_json"])

    def save_result(self, ticket_id: str, payload_hash: str, response: TriageResponse) -> bool:
        """
        Atomically saves the triage result into the ledger using INSERT OR IGNORE.
        
        Returns:
            True if inserted, False if already present (duplicate/conflict).
        """
        created_at = datetime.now(timezone.utc).isoformat()
        refund_approved_int = 1 if response.refund.approved else 0

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO triage_ledger
                (ticket_id, payload_hash, response_json, refund_approved, refund_amount_inr, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket_id,
                    payload_hash,
                    response.model_dump_json(),
                    refund_approved_int,
                    response.refund.amount_inr,
                    created_at,
                ),
            )
            conn.commit()
            inserted = cursor.rowcount > 0

        if inserted:
            log_event(
                event_type="idempotency_record_saved",
                ticket_id=ticket_id,
                payload_hash=payload_hash[:8],
                refund_approved=response.refund.approved,
                refund_amount=response.refund.amount_inr,
            )
        else:
            log_event(
                event_type="idempotency_duplicate_ignored",
                ticket_id=ticket_id,
                payload_hash=payload_hash[:8],
            )

        return inserted

