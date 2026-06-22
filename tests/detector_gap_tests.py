import asyncio
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hunt_engine import (
    hunt_clickjacking,
    hunt_cors,
    hunt_dom_xss,
    hunt_session_security,
)
from scope_policy import scope_policy


async def run_tests():
    original_scope = scope_policy.to_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/cors":
            if request.method == "POST":
                origin = request.headers.get("origin", "")
                return httpx.Response(
                    200,
                    headers={
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    },
                    text="Got it!",
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    "<script>var xhr=new XMLHttpRequest();"
                    "xhr.open('POST', location.href, true);xhr.send();</script>"
                ),
            )
        if path == "/frameable":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "X-Frame-Options": "ALLOWALL",
                },
                text="<html><body>Technical framing fixture</body></html>",
            )
        if path == "/settings":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<html><form><input type="password" name="password"></form></html>',
            )
        if path == "/cookie":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Set-Cookie": "auth_token=secret-value-123; HttpOnly; Secure",
                },
                text="<html>secret-value-123</html>",
            )
        if path == "/inline-dom":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    "<html><script>\n"
                    "var payload = document.referrer;\n"
                    "eval(payload);\n"
                    "</script></html>"
                ),
            )
        return httpx.Response(404)

    try:
        scope_policy.update(
            {
                **original_scope,
                "allowed_domains": ["example.test"],
                "denied_domains": [],
                "active_testing_enabled": True,
                "passive_only_mode": False,
                "emergency_stop": False,
            },
            persist=False,
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            cors = await hunt_cors(client, "https://example.test/cors")
            frameable = await hunt_clickjacking(
                client, ["https://example.test/frameable"]
            )
            sensitive_frame = await hunt_clickjacking(
                client, ["https://example.test/settings"]
            )
            cookie = await hunt_session_security(
                client, ["https://example.test/cookie"]
            )
            dom = await hunt_dom_xss(
                client, ["https://example.test/inline-dom"]
            )

        assert cors and cors[0]["method"] == "POST"
        assert cors[0]["exploitability_status"] == "needs_manual_validation"
        assert frameable and frameable[0]["vuln_type"] == "frameable_page_candidate"
        assert frameable[0]["severity"] == "LOW"
        assert sensitive_frame and sensitive_frame[0]["vuln_type"] == "clickjacking_candidate"
        assert cookie and any(
            item["vuln_type"] == "HttpOnly Cookie Value Exposed in Page Content"
            for item in cookie
        )
        assert dom and dom[0]["source_name"] == "document.referrer"
        assert dom[0]["sink_name"] == "eval"
        print("DETECTOR GAP TESTS: PASS")
    finally:
        scope_policy.update(original_scope, persist=False)


if __name__ == "__main__":
    asyncio.run(run_tests())
