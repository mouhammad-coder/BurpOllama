import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth_session import SessionProfile
from dual_session import DualSessionMatrix


def _jwt(expiry: int) -> str:
    def encode(value):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return "{}.{}.signature".format(encode({"alg": "none"}), encode({"exp": expiry}))


def run_tests():
    future = int(time.time()) + 120
    token = _jwt(future)
    profile = SessionProfile.create(
        "Standard user",
        cookie="session=secret-cookie",
        token=token,
        custom_headers={"X-Tenant": "test-tenant"},
    )
    status = profile.public_status()
    assert profile.configured
    assert status["session_id"].startswith("SES-")
    assert status["role"] == "Standard user"
    assert status["expiring_soon"]
    assert not status["expired"]
    assert set(status["auth_types"]) == {"cookie", "bearer", "custom_headers"}
    headers = profile.headers({"Accept": "application/json"})
    assert headers["Cookie"] == "session=secret-cookie"
    assert headers["Authorization"].startswith("Bearer ")
    assert "secret-cookie" not in str(profile)
    assert token not in repr(profile)

    duplicate = SessionProfile.create(
        "Different display role",
        cookie="session=secret-cookie",
        token=token,
        custom_headers={"X-Tenant": "test-tenant"},
    )
    assert duplicate.session_id == profile.session_id

    try:
        SessionProfile.create("User", cookie="ok\r\nX-Evil: injected")
        raise AssertionError("CRLF cookie was accepted")
    except ValueError:
        pass
    try:
        SessionProfile.create(
            "User", custom_headers={"Authorization": "Bearer duplicate"}
        )
        raise AssertionError("Sensitive custom header was accepted")
    except ValueError:
        pass

    matrix = DualSessionMatrix()
    matrix.configure(
        session_a_cookie="session=a",
        session_b_token=_jwt(int(time.time()) + 3600),
        session_a_role="Member",
        session_b_role="Administrator",
    )
    stats = matrix.stats
    assert stats["configured"]
    assert stats["session_a"]["role"] == "Member"
    assert stats["session_b"]["role"] == "Administrator"
    assert "session=a" not in json.dumps(stats)

    print("AUTH SESSION TESTS: PASS")


if __name__ == "__main__":
    run_tests()
