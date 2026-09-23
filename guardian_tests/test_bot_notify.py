"""The notice webhook is a sink: it accepts a notice or refuses, nothing else.

A leaked secret must not become an API, and a wrong one must not reveal
whether the endpoint exists.
"""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("maubot")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bot"))

from guardian_bot import (  # noqa: E402
    NOTIFY_MAX_BODY,
    parse_notify_request,
)

SECRET = "s3cret"


def body(text: str = "guardian: blocked invite") -> bytes:
    return json.dumps({"text": text}).encode()


def test_good_secret_returns_the_text() -> None:
    assert parse_notify_request(f"Bearer {SECRET}", body(), SECRET) == (
        200,
        "guardian: blocked invite",
    )


def test_wrong_secret_is_refused() -> None:
    assert parse_notify_request("Bearer wrong", body(), SECRET) == (401, None)


def test_missing_header_is_refused() -> None:
    assert parse_notify_request(None, body(), SECRET) == (401, None)


def test_non_bearer_header_is_refused() -> None:
    assert parse_notify_request(f"Basic {SECRET}", body(), SECRET) == (401, None)


def test_secret_prefix_is_not_enough() -> None:
    """compare_digest, not startswith."""
    assert parse_notify_request("Bearer s3c", body(), SECRET) == (401, None)


def test_unconfigured_secret_refuses_everything() -> None:
    assert parse_notify_request("Bearer anything", body(), None) == (503, None)
    assert parse_notify_request("Bearer anything", body(), "") == (503, None)


def test_malformed_json_is_refused() -> None:
    assert parse_notify_request(f"Bearer {SECRET}", b"not json", SECRET) == (400, None)


def test_non_object_json_is_refused() -> None:
    assert parse_notify_request(f"Bearer {SECRET}", b'["a"]', SECRET) == (400, None)


def test_missing_or_empty_text_is_refused() -> None:
    assert parse_notify_request(f"Bearer {SECRET}", b"{}", SECRET) == (400, None)
    assert parse_notify_request(f"Bearer {SECRET}", body("   "), SECRET) == (400, None)
    assert parse_notify_request(f"Bearer {SECRET}", b'{"text": 5}', SECRET) == (400, None)


def test_oversized_body_is_refused_before_parsing() -> None:
    huge = b"x" * (NOTIFY_MAX_BODY + 1)
    assert parse_notify_request(f"Bearer {SECRET}", huge, SECRET) == (413, None)


def test_invalid_utf8_is_refused() -> None:
    assert parse_notify_request(f"Bearer {SECRET}", b"\xff\xfe", SECRET) == (400, None)
