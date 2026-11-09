import pytest

from ircopilot.inspect_compose import ComposeError, inspect_compose_text, load_compose

RISKY = """
services:
  web:
    image: nginx
    privileged: true
    ports: ["8080:80", "127.0.0.1:9000:9000"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc
    environment:
      DB_PASSWORD: hunter2
      SAFE_REF: ${FROM_ENV}
    depends_on:
      db:
        condition: service_healthy
      ghost: {}
  db:
    image: postgres:16.4
    ports: ["8080:5432"]
    cap_add: [SYS_ADMIN]
    network_mode: host
"""


def test_risky_compose_findings() -> None:
    report = inspect_compose_text(RISKY, "compose.yml")
    rules = {(f.rule, f.service) for f in report.findings}
    for expected in [
        ("privileged", "web"),
        ("container_runtime_socket", "web"),
        ("sensitive_bind_mount", "web"),
        ("port_all_interfaces", "web"),
        ("unpinned_image", "web"),
        ("inline_secret", "web"),
        ("unknown_dependency", "web"),
        ("healthy_condition_without_healthcheck", "web"),
        ("dangerous_capabilities", "db"),
        ("host_network_mode", "db"),
        ("host_port_conflict", None),
    ]:
        assert expected in rules, expected
    assert report.findings[0].severity == "high"


def test_env_values_never_returned() -> None:
    dumped = str(inspect_compose_text(RISKY, "compose.yml").to_dict())
    assert "hunter2" not in dumped
    assert "DB_PASSWORD" in dumped  # key names are fine


def test_localhost_port_not_flagged() -> None:
    report = inspect_compose_text("services:\n  a:\n    image: x:1\n    ports: ['127.0.0.1:80:80']\n", "c.yml")
    assert not any(f.rule == "port_all_interfaces" for f in report.findings)


def test_billion_laughs_rejected() -> None:
    bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    prev = "a"
    for name in "bcdefgh":
        bomb += f"{name}: &{name} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
        prev = name
    with pytest.raises(ComposeError, match="too complex"):
        load_compose(bomb)


def test_recursive_alias_rejected() -> None:
    with pytest.raises(ComposeError):
        load_compose("services: &s\n  x: *s\n")


def test_unsafe_tags_and_bad_yaml_rejected_safely() -> None:
    with pytest.raises(ComposeError):
        load_compose("services: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(ComposeError, match="line") as exc:
        load_compose("services:\n  web: [unclosed\n  password: hunter2\n")
    assert "hunter2" not in str(exc.value)
    with pytest.raises(ComposeError):
        load_compose("- just\n- a list\n")
    with pytest.raises(ComposeError):
        load_compose("a: 1\n---\nb: 2\n")


def test_weird_types_do_not_crash() -> None:
    report = inspect_compose_text("services:\n  a: 5\n  b:\n    deploy: nope\n    ports: 80\n    environment: [X]\n", "c.yml")
    assert any(f.rule == "invalid_service" for f in report.findings)
