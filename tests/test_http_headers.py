from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "http_headers.py"
SPEC = importlib.util.spec_from_file_location("http_headers", SCRIPT)
http_headers = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(http_headers)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def headers_text(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


class ParseRawHeadersTest(unittest.TestCase):
    def test_parses_status_and_header_lines(self) -> None:
        raw = headers_text([
            "status: 200",
            "Content-Type: text/html",
            "Strict-Transport-Security: max-age=31536000",
        ])
        parsed = http_headers.parse_raw_headers(raw)
        self.assertEqual(parsed["status"], "200")
        self.assertEqual(parsed["content-type"], "text/html")
        self.assertEqual(parsed["strict-transport-security"], "max-age=31536000")

    def test_ignores_empty_and_comment_lines(self) -> None:
        raw = headers_text([
            "",
            "# comment",
            "status: 200",
            "   ",
            "X-Frame-Options: DENY",
        ])
        parsed = http_headers.parse_raw_headers(raw)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed["x-frame-options"], "DENY")

    def test_strips_whitespace_from_values(self) -> None:
        raw = headers_text([
            "status: 200",
            "X-Content-Type-Options:   nosniff   ",
        ])
        parsed = http_headers.parse_raw_headers(raw)
        self.assertEqual(parsed["x-content-type-options"], "nosniff")

    def test_handles_multiple_set_cookie_headers(self) -> None:
        raw = headers_text([
            "status: 200",
            "Set-Cookie: sessionid=abc; Secure; HttpOnly",
            "Set-Cookie: csrftoken=xyz; SameSite=Lax",
        ])
        parsed = http_headers.parse_raw_headers(raw)
        self.assertEqual(parsed["set-cookie"], "sessionid=abc; Secure; HttpOnly")
        self.assertEqual(parsed["_set-cookie_1"], "csrftoken=xyz; SameSite=Lax")

    def test_header_name_normalized_to_lowercase(self) -> None:
        raw = headers_text([
            "STATUS: 200",
            "Strict-Transport-Security: max-age=31536000",
        ])
        parsed = http_headers.parse_raw_headers(raw)
        self.assertIn("strict-transport-security", parsed)
        self.assertIn("status", parsed)


class CheckHSTSTest(unittest.TestCase):
    def test_missing_hsts_on_https_is_fail(self) -> None:
        result = http_headers.check_hsts({}, is_https=True, has_error=False)
        self.assertEqual(result["status"], "fail")
        self.assertIn("missing", result["finding"].lower())

    def test_missing_hsts_on_http_is_warn(self) -> None:
        result = http_headers.check_hsts({}, is_https=False, has_error=False)
        self.assertEqual(result["status"], "warn")

    def test_hsts_with_strong_max_age_is_pass(self) -> None:
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        result = http_headers.check_hsts(headers, is_https=True, has_error=False)
        self.assertEqual(result["status"], "pass")

    def test_hsts_with_short_max_age_is_warn(self) -> None:
        headers = {"strict-transport-security": "max-age=3600"}
        result = http_headers.check_hsts(headers, is_https=True, has_error=False)
        self.assertEqual(result["status"], "warn")
        self.assertIn("3600", result["finding"])

    def test_hsts_max_age_zero_is_fail(self) -> None:
        headers = {"strict-transport-security": "max-age=0"}
        result = http_headers.check_hsts(headers, is_https=True, has_error=False)
        self.assertEqual(result["status"], "fail")

    def test_hsts_connection_error_is_fail(self) -> None:
        result = http_headers.check_hsts({}, is_https=False, has_error=True)
        self.assertEqual(result["status"], "fail")
        self.assertIn("unreachable", result["finding"].lower())


class CheckCSPTest(unittest.TestCase):
    def test_csp_without_unsafe_directives_is_pass(self) -> None:
        headers = {"content-security-policy": "default-src 'self'; script-src 'self'"}
        result = http_headers.check_csp(headers)
        self.assertEqual(result["status"], "pass")

    def test_csp_with_unsafe_inline_is_warn(self) -> None:
        headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
        result = http_headers.check_csp(headers)
        self.assertEqual(result["status"], "warn")
        self.assertIn("unsafe-inline", result["finding"])

    def test_csp_with_unsafe_eval_is_warn(self) -> None:
        headers = {"content-security-policy": "default-src 'self'; script-src 'unsafe-eval'"}
        result = http_headers.check_csp(headers)
        self.assertEqual(result["status"], "warn")
        self.assertIn("unsafe-eval", result["finding"])

    def test_missing_csp_is_fail(self) -> None:
        result = http_headers.check_csp({})
        self.assertEqual(result["status"], "fail")
        self.assertIn("missing", result["finding"].lower())

    def test_csp_with_both_unsafe_directives_is_warn(self) -> None:
        headers = {"content-security-policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"}
        result = http_headers.check_csp(headers)
        self.assertEqual(result["status"], "warn")

    def test_csp_report_only_is_noted(self) -> None:
        headers = {"content-security-policy-report-only": "default-src 'self'"}
        result = http_headers.check_csp(headers)
        self.assertEqual(result["status"], "fail")
        self.assertIn("report-only", result["finding"].lower())


class CheckXContentTypeOptionsTest(unittest.TestCase):
    def test_nosniff_is_pass(self) -> None:
        headers = {"x-content-type-options": "nosniff"}
        result = http_headers.check_x_content_type_options(headers)
        self.assertEqual(result["status"], "pass")

    def test_missing_is_fail(self) -> None:
        result = http_headers.check_x_content_type_options({})
        self.assertEqual(result["status"], "fail")


class CheckXFrameOptionsTest(unittest.TestCase):
    def test_deny_is_pass(self) -> None:
        result = http_headers.check_x_frame_options({"x-frame-options": "DENY"})
        self.assertEqual(result["status"], "pass")

    def test_sameorigin_is_pass(self) -> None:
        result = http_headers.check_x_frame_options({"x-frame-options": "SAMEORIGIN"})
        self.assertEqual(result["status"], "pass")

    def test_missing_is_warn(self) -> None:
        result = http_headers.check_x_frame_options({})
        self.assertEqual(result["status"], "warn")


class CheckReferrerPolicyTest(unittest.TestCase):
    def test_strict_origin_when_cross_origin_is_pass(self) -> None:
        result = http_headers.check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})
        self.assertEqual(result["status"], "pass")

    def test_no_referrer_is_pass(self) -> None:
        result = http_headers.check_referrer_policy({"referrer-policy": "no-referrer"})
        self.assertEqual(result["status"], "pass")

    def test_unsafe_url_is_fail(self) -> None:
        result = http_headers.check_referrer_policy({"referrer-policy": "unsafe-url"})
        self.assertEqual(result["status"], "fail")

    def test_missing_is_warn(self) -> None:
        result = http_headers.check_referrer_policy({})
        self.assertEqual(result["status"], "warn")


class CheckPermissionsPolicyTest(unittest.TestCase):
    def test_present_is_pass(self) -> None:
        headers = {"permissions-policy": "camera=(), microphone=()"}
        result = http_headers.check_permissions_policy(headers)
        self.assertEqual(result["status"], "pass")

    def test_missing_is_warn(self) -> None:
        result = http_headers.check_permissions_policy({})
        self.assertEqual(result["status"], "warn")


class CheckCORSTest(unittest.TestCase):
    def test_no_cors_headers_is_pass(self) -> None:
        result = http_headers.check_cors({})
        self.assertEqual(result["status"], "pass")

    def test_wildcard_origin_without_credentials_is_warn(self) -> None:
        result = http_headers.check_cors({"access-control-allow-origin": "*"})
        self.assertEqual(result["status"], "warn")

    def test_wildcard_origin_with_credentials_is_fail(self) -> None:
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        result = http_headers.check_cors(headers)
        self.assertEqual(result["status"], "fail")

    def test_specific_origin_is_pass(self) -> None:
        result = http_headers.check_cors({"access-control-allow-origin": "https://example.com"})
        self.assertEqual(result["status"], "pass")


class CheckCookiesTest(unittest.TestCase):
    def test_no_set_cookie_headers_is_pass(self) -> None:
        results = http_headers.check_cookies({})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "pass")
        self.assertIn("no set-cookie", results[0]["finding"].lower())

    def test_secure_cookie_is_pass(self) -> None:
        headers = {"set-cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "pass")

    def test_missing_secure_flag_is_fail(self) -> None:
        headers = {"set-cookie": "sessionid=abc; HttpOnly"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(results[0]["status"], "fail")
        self.assertIn("Secure", results[0]["finding"])

    def test_missing_httponly_flag_is_warn(self) -> None:
        headers = {"set-cookie": "sessionid=abc; Secure; SameSite=Lax"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(results[0]["status"], "warn")
        self.assertIn("HttpOnly", results[0]["finding"])

    def test_samesite_none_without_secure_is_fail(self) -> None:
        headers = {"set-cookie": "sessionid=abc; SameSite=None; HttpOnly"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(results[0]["status"], "fail")

    def test_samesite_none_with_secure_is_pass(self) -> None:
        headers = {"set-cookie": "sessionid=abc; Secure; SameSite=None; HttpOnly"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(results[0]["status"], "pass")

    def test_redacted_cookie_value_is_pass_with_note(self) -> None:
        headers = {"set-cookie": "[REDACTED]"}
        results = http_headers.check_cookies(headers)
        self.assertEqual(results[0]["status"], "pass")
        self.assertIn("redacted", results[0]["finding"].lower())

    def test_multiple_set_cookie_headers(self) -> None:
        headers = {
            "set-cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
            "_set-cookie_1": "tracking=xyz",
        }
        results = http_headers.check_cookies(headers)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["status"], "pass")
        self.assertEqual(results[1]["status"], "fail")


class EvaluateTest(unittest.TestCase):
    def test_all_pass_headers_produce_pass_status(self) -> None:
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "set-cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
        }
        result = http_headers.evaluate("https://example.com", headers)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["failed"], 0)

    def test_one_fail_makes_overall_status_fail(self) -> None:
        headers = {
            "x-content-type-options": "nosniff",
        }
        result = http_headers.evaluate("https://example.com", headers)
        self.assertEqual(result["status"], "fail")

    def test_warn_without_fail_gives_warn_status(self) -> None:
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "set-cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
        }
        result = http_headers.evaluate("https://example.com", headers)
        self.assertEqual(result["status"], "warn")

    def test_source_is_set_from_target_url(self) -> None:
        result = http_headers.evaluate("https://api.example.com", {})
        self.assertEqual(result["source"], "https://api.example.com")

    def test_failed_checks_are_listed(self) -> None:
        headers = {"x-content-type-options": "nosniff"}
        result = http_headers.evaluate("https://example.com", headers)
        self.assertIn("csp", result["failed_checks"])
        self.assertGreater(len(result["findings"]), 0)


class RunTest(unittest.TestCase):
    def test_passing_headers_produces_artifacts_and_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text(headers_text([
                "status: 200",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "Content-Security-Policy: default-src 'self'",
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: DENY",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: camera=()",
                "Set-Cookie: sessionid=abc; Secure; HttpOnly; SameSite=Lax",
            ]))

            rc = http_headers.run("https://example.com", raw_file, reports)
            evidence = reports / "F6" / "web-policies.json"
            results = reports / "F6" / "web-policies-results.json"

            self.assertEqual(rc, 0)
            self.assertTrue(evidence.exists())
            self.assertTrue(results.exists())
            data = json.loads(results.read_text())
            self.assertEqual(data["status"], "pass")

    def test_failing_headers_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text(headers_text([
                "status: 200",
                "Set-Cookie: sessionid=abc",
            ]))

            rc = http_headers.run("https://example.com", raw_file, reports)

            self.assertEqual(rc, 1)

    def test_warn_headers_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text(headers_text([
                "status: 200",
                "Strict-Transport-Security: max-age=31536000",
                "Content-Security-Policy: default-src 'self'",
                "X-Content-Type-Options: nosniff",
                "Set-Cookie: sessionid=abc; Secure; HttpOnly; SameSite=Lax",
            ]))

            rc = http_headers.run("https://example.com", raw_file, reports)

            self.assertEqual(rc, 0)

    def test_missing_raw_headers_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            with self.assertRaises(RuntimeError):
                http_headers.run("https://example.com", raw_file, reports)

    def test_empty_headers_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text("")

            with self.assertRaises(RuntimeError):
                http_headers.run("https://example.com", raw_file, reports)

    def test_connection_error_produces_error_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text(headers_text([
                "URLError: connection refused",
            ]))

            rc = http_headers.run("https://example.com", raw_file, reports)
            results = reports / "F6" / "web-policies-results.json"

            self.assertEqual(rc, 1)
            data = json.loads(results.read_text())
            self.assertEqual(data["status"], "fail")
            self.assertGreater(len(data["failed_checks"]), 0)


class CLITest(unittest.TestCase):
    def test_cli_with_valid_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            raw_file = reports / "F6" / "http-headers.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            raw_file.write_text(headers_text([
                "status: 200",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "Content-Security-Policy: default-src 'self'",
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: DENY",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: camera=()",
                "Set-Cookie: sessionid=abc; Secure; HttpOnly; SameSite=Lax",
            ]))

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "https://example.com",
                    str(raw_file),
                    str(reports),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)

    def test_cli_usage_without_args(self) -> None:
        result = subprocess.run(
            ["python3", str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
