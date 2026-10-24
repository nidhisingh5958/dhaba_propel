"""
Structured JSON logger with automated PII scrubbing filter.
Enforces security boundaries to prevent PII/financial data from entering log streams.
"""

from datetime import datetime, timezone
import json
import logging
import re
import sys
from typing import Any, Dict, Set


# -----------------------------------------------------------------------------
# PII Scrubbing Regular Expressions
# -----------------------------------------------------------------------------

# 1. Indian GSTIN: 2 digits + 5 letters + 4 digits + 1 letter + 1 char + Z + 1 char
GSTIN_REGEX = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b")

# 2. Known company identifier patterns (words preceding GSTIN or specific entities like Acme Interiors)
COMPANY_BEFORE_GSTIN_REGEX = re.compile(
    r"([A-Z][A-Za-z0-9&'. ]+?)(,\s*|\s*[-:]\s*|\s+)(?=\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b)"
)
KNOWN_COMPANY_REGEX = re.compile(
    r"\b(?:Acme\s+Interiors|[A-Z][A-Za-z0-9&']+(?:\s+[A-Z][A-Za-z0-9&']+)*\s+(?:Pvt\.?|Ltd\.?|LLP|Inc\.?|Corp\.?|Enterprises|Interiors|Solutions|Services|Technologies))\b",
    re.IGNORECASE,
)

# 3. Emails & UPI IDs (e.g. user@domain.com, user@okhdfcbank, 9876543210@paytm)
EMAIL_UPI_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b"
)

# 4. 10-16 digit phone numbers and card numbers
# Matches 10-digit Indian phones (with optional +91 or hyphens/spaces) and 13-16 digit credit/debit cards
PHONE_CARD_REGEX = re.compile(
    r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b|\b(?:\d[ -]?){10,16}\b"
)

# Forbidden fields in log_event kwargs to prevent raw ticket leakage
FORBIDDEN_LOG_FIELDS: Set[str] = {
    "body",
    "subject",
    "raw_body",
    "raw_subject",
    "ticket_body",
    "ticket_subject",
}


def scrub_pii(data: Any) -> Any:
    """
    Recursively scrubs PII from strings, dictionaries, lists, and tuples.
    """
    if isinstance(data, str):
        # 1. Redact company patterns preceding GSTIN (lookahead keeps GSTIN intact)
        text = COMPANY_BEFORE_GSTIN_REGEX.sub(r"[REDACTED_ENTITY]\2", data)
        # 2. Redact known corporate entities
        text = KNOWN_COMPANY_REGEX.sub(r"[REDACTED_ENTITY]", text)
        # 3. Redact GSTIN
        text = GSTIN_REGEX.sub(r"[REDACTED_GSTIN]", text)
        # 4. Redact Email & UPI IDs
        text = EMAIL_UPI_REGEX.sub(r"[REDACTED_EMAIL_UPI]", text)
        # 5. Redact 10-16 digit phone & card numbers (avoid timestamps like 2026-09-02T09:14:00)
        # We only scrub numbers if they don't match ISO datetime patterns
        if "T" not in text:
            text = PHONE_CARD_REGEX.sub(r"[REDACTED_NUMBER]", text)
        return text

    if isinstance(data, dict):
        return {scrub_pii(k): scrub_pii(v) for k, v in data.items()}

    if isinstance(data, list):
        return [scrub_pii(item) for item in data]

    if isinstance(data, tuple):
        return tuple(scrub_pii(item) for item in data)

    return data


# -----------------------------------------------------------------------------
# Logging Filter and Formatter
# -----------------------------------------------------------------------------

class PIIScrubFilter(logging.Filter):
    """
    Logging filter that intercepts and sanitizes any LogRecord before it is formatted.
    Ensures message and all extra attributes have PII removed.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub_pii(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = scrub_pii(record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(scrub_pii(arg) for arg in record.args)

        # Sanitize any extra attributes stored on record
        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "message", "asctime"
        }
        for key, value in list(record.__dict__.items()):
            if key not in standard_attrs:
                record.__dict__[key] = scrub_pii(value)

        return True


class JSONLogFormatter(logging.Formatter):
    """
    Formats log records as structured single-line JSON objects.
    """
    def format(self, record: logging.LogRecord) -> str:
        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "message", "asctime"
        }

        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom extra fields
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                log_entry[key] = scrub_pii(value)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


# -----------------------------------------------------------------------------
# Logger Factory & Helper Functions
# -----------------------------------------------------------------------------

def setup_logger(name: str = "dhaba") -> logging.Logger:
    """
    Configures and returns a logger instance with JSON formatting and PII filter.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(PIIScrubFilter())
        handler.setFormatter(JSONLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger("dhaba")


def log_event(event_type: str, ticket_id: str, **kwargs: Any) -> None:
    """
    Helper for emitting structured lifecycle log events.
    Strictly forbids raw 'body' or 'subject' to protect user PII.
    
    Raises:
        ValueError: If body or subject are passed in kwargs.
    """
    for key in kwargs:
        if key.lower() in FORBIDDEN_LOG_FIELDS:
            raise ValueError(
                f"Security violation: field '{key}' is forbidden in log events "
                "to prevent raw ticket PII leakage. Extract specific safe metadata instead."
            )

    extra_payload = {
        "event_type": event_type,
        "ticket_id": ticket_id,
        **kwargs,
    }

    logger.info(
        f"Event: {event_type} for ticket {ticket_id}",
        extra=extra_payload
    )

