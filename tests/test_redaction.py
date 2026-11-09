import pytest

from ircopilot.inspect_log import analyze_log
from ircopilot.safety.redact import redact, redact_text

SECRETS = [
    ("AWS key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("token ghp_" + "a" * 36, "ghp_" + "a" * 36),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij"),
    ("key=AIza" + "B" * 35, "AIza" + "B" * 35),
    ("stripe sk_live_" + "c" * 24, "sk_live_" + "c" * 24),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "eyJhbGciOiJIUzI1NiJ9"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("connecting to postgres://app:hunter2@db:5432/app", "hunter2"),
    ("DB_PASSWORD=supersecret123", "supersecret123"),
    ('{"api_key": "k-123456789"}', "k-123456789"),
    ("client_secret: 'abc123xyz'", "abc123xyz"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----", "MIIEow"),
]


@pytest.mark.parametrize(("text", "secret"), SECRETS)
def test_secrets_are_redacted(text: str, secret: str) -> None:
    out = redact(text)
    assert secret not in out.text
    assert "[REDACTED" in out.text
    assert out.total >= 1


def test_plain_text_and_interpolation_untouched() -> None:
    text = "2024-01-01 ERROR connection refused to db:5432 (retry 3)\nPASSWORD=${DB_PASSWORD}"
    assert redact_text(text) == text


def test_url_username_kept_password_removed() -> None:
    assert redact_text("redis://user:pa55word@cache:6379") == "redis://user:[REDACTED]@cache:6379"


def test_log_report_never_contains_secret() -> None:
    log = "2024 ERROR OOMKilled password=hunter2 token=abcd1234efgh\nAKIAIOSFODNN7EXAMPLE connection refused"
    report = analyze_log(log, "app.log")
    dumped = str(report.to_dict()) + report.summary_for_model()
    for s in ("hunter2", "abcd1234efgh", "AKIAIOSFODNN7EXAMPLE"):
        assert s not in dumped
    assert report.redactions
    assert {f.rule for f in report.findings} >= {"oom_killed", "connection_refused"}
