"""Static, read-only analysis of a Docker Compose file. Nothing in the file is executed or interpolated."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import yaml

from ircopilot.models import SEVERITY_ORDER, Finding, Severity
from ircopilot.safety.redact import is_secret_key, redact_text
from ircopilot.safety.text import clean_text, truncate

MAX_NODES = 50_000
MAX_DEPTH = 40
MAX_SERVICES = 500
COMPOSE_SUFFIXES = frozenset({".yml", ".yaml"})

_SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/var/run", "/run", "/var/lib/docker", "/home")
_SOCKET_RE = re.compile(r"docker\.sock|containerd\.sock|crio\.sock|\\\\\.\\pipe\\docker_engine", re.IGNORECASE)
_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}


class ComposeError(ValueError):
    """Parsing failed. Messages never echo file content."""


def _check_complexity(root: Any) -> None:
    """Bound traversal so alias expansion ('billion laughs') and recursive anchors are rejected."""
    budget = MAX_NODES
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        budget -= 1
        if budget < 0:
            raise ComposeError(f"YAML document is too complex (more than {MAX_NODES} nodes after alias expansion).")
        if depth > MAX_DEPTH:
            raise ComposeError(f"YAML nesting is deeper than {MAX_DEPTH} levels.")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
            stack.extend((k, depth + 1) for k in node if isinstance(k, (dict, list, tuple)))
        elif isinstance(node, (list, tuple)):
            stack.extend((v, depth + 1) for v in node)


def load_compose(text: str) -> dict[str, Any]:
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f" near line {mark.line + 1}" if mark is not None else ""
        raise ComposeError(f"Invalid YAML{where}.") from None
    except (yaml.YAMLError, RecursionError, ValueError, TypeError):
        raise ComposeError("Invalid or unsupported YAML.") from None
    if len(docs) != 1:
        raise ComposeError("Expected exactly one YAML document.")
    data = docs[0]
    _check_complexity(data)
    if not isinstance(data, dict):
        raise ComposeError("Top level of a Compose file must be a mapping.")
    return data


def _s(value: Any, limit: int = 200) -> str:
    return truncate(clean_text(str(value)), limit)


@dataclass
class ServiceSummary:
    name: str
    image: str | None
    build: bool
    ports: list[str]
    depends_on: list[str]
    healthcheck: bool
    restart: str | None
    user: str | None
    env_keys: list[str]


@dataclass
class ComposeReport:
    path: str
    services: list[ServiceSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule: str, sev: Severity, msg: str, service: str | None = None, q: str | None = None) -> None:
        self.findings.append(Finding(rule=rule, severity=sev, message=msg, service=service, doc_query=q))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "services": [vars(s) for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "note": "Static analysis only; environment values are never returned. Nothing was executed.",
        }

    def doc_query(self) -> str:
        qs = [f.doc_query for f in self.findings if f.doc_query and f.severity in ("high", "medium")]
        return "; ".join(dict.fromkeys(qs))[:500]

    def summary_for_model(self, max_items: int = 20) -> str:
        names = ", ".join(s.name for s in self.services[:30])
        out = [f"Compose file: {self.path}. Services: {names}. Findings:"]
        out += [f"- [{f.severity}] {f.service or '-'}: {f.rule}: {f.message}" for f in self.findings[:max_items]]
        return "\n".join(out)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.keys())
    return [value]


def _dig(data: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _env_items(env: Any) -> list[tuple[str, str | None]]:
    if isinstance(env, dict):
        return [(_s(k, 100), None if v is None else str(v)) for k, v in env.items()]
    items = []
    for entry in _as_list(env):
        key, sep, val = str(entry).partition("=")
        items.append((_s(key, 100), val if sep else None))
    return items


def _port_entries(ports: Any) -> list[tuple[str, str | None, str | None]]:
    """Return (display, host_ip, host_port) for each published port."""
    out = []
    for p in _as_list(ports):
        if isinstance(p, dict):
            ip, published = p.get("host_ip"), p.get("published")
            out.append((_s(p, 120), None if ip is None else str(ip), None if published is None else str(published)))
            continue
        text = str(p).split("/")[0]
        if text.startswith("["):  # IPv6 host address
            ip, _, rest = text[1:].partition("]")
            parts = [ip, *rest.lstrip(":").split(":")]
        else:
            parts = text.split(":")
        if len(parts) == 1:
            out.append((_s(p, 60), None, None))  # container-only port: random host port on all interfaces
        elif len(parts) == 2:
            out.append((_s(p, 60), None, parts[0]))
        else:
            out.append((_s(p, 60), ":".join(parts[:-2]), parts[-2]))
    return out


def _volume_sources(volumes: Any) -> list[str]:
    out = []
    for v in _as_list(volumes):
        if isinstance(v, dict):
            if v.get("type", "bind") == "bind" or "source" in v:
                out.append(str(v.get("source", "")))
        else:
            text = str(v)
            # Windows drive letters ("C:\\x:/y") make naive splitting ambiguous; keep the first segment.
            m = re.match(r"^([A-Za-z]:[\\/][^:]*|[^:]+)", text)
            out.append(m.group(1) if m else text)
    return out


def analyze_compose(data: dict[str, Any], display_path: str) -> ComposeReport:
    report = ComposeReport(display_path)
    services = data.get("services")
    if not isinstance(services, dict) or not services:
        report.add("no_services", "high", "No `services` mapping found; this does not look like a Compose file.")
        return report
    if len(services) > MAX_SERVICES:
        raise ComposeError(f"Too many services (limit {MAX_SERVICES}).")

    names = {str(n) for n in services}
    host_ports: dict[str, list[str]] = defaultdict(list)

    for raw_name, svc in services.items():
        name = _s(raw_name, 80)
        if not isinstance(svc, dict):
            report.add("invalid_service", "high", "Service definition is not a mapping.", name)
            continue
        image = svc.get("image")
        env = _env_items(svc.get("environment"))
        ports = _port_entries(svc.get("ports"))
        depends = svc.get("depends_on")
        dep_names = [str(d) for d in _as_list(depends)]
        summary = ServiceSummary(
            name=name,
            image=None if image is None else _s(redact_text(str(image))),
            build="build" in svc,
            ports=[p[0] for p in ports],
            depends_on=[_s(d, 80) for d in dep_names],
            healthcheck=isinstance(svc.get("healthcheck"), dict) and not svc["healthcheck"].get("disable", False),
            restart=None if svc.get("restart") is None else _s(svc.get("restart"), 40),
            user=None if svc.get("user") is None else _s(svc.get("user"), 40),
            env_keys=[k for k, _ in env][:100],
        )
        report.services.append(summary)

        if svc.get("privileged") is True:
            report.add("privileged", "high", "Runs as a privileged container (full host device access).", name, "docker privileged container security")
        for src in _volume_sources(svc.get("volumes")):
            if _SOCKET_RE.search(src):
                report.add("container_runtime_socket", "high", "Mounts the container runtime socket, which grants root-equivalent host control.", name, "docker daemon socket security")
            elif src.rstrip("/\\") in _SENSITIVE_MOUNTS or src in ("/", "C:\\", "C:/") or re.fullmatch(r"[A-Za-z]:[\\/]?", src):
                report.add("sensitive_bind_mount", "high", f"Bind-mounts sensitive host path {_s(src, 60)!r}.", name, "docker bind mounts read-only")
        for key in ("network_mode", "pid", "ipc", "uts", "userns_mode"):
            if str(svc.get(key, "")).lower() == "host":
                report.add(f"host_{key}", "high" if key in ("pid", "network_mode") else "medium", f"Uses `{key}: host`, removing namespace isolation.", name, "docker network host mode")
        caps = {str(c).upper().removeprefix("CAP_") for c in _as_list(svc.get("cap_add"))}
        if bad := sorted(caps & _DANGEROUS_CAPS):
            report.add("dangerous_capabilities", "high", f"Adds powerful capabilities: {', '.join(bad)}.", name, "docker runtime privilege linux capabilities")
        for opt in _as_list(svc.get("security_opt")):
            if "unconfined" in str(opt).lower():
                report.add("unconfined_security_profile", "high", f"Disables a security profile ({_s(opt, 60)}).", name, "docker seccomp apparmor security")
        for display, ip, hport in ports:
            if ip is None or ip in ("0.0.0.0", "::", ""):
                report.add("port_all_interfaces", "medium", f"Port {display} is published on all host interfaces; bind to 127.0.0.1 if only local access is needed.", name, "docker publish port localhost 127.0.0.1")
            if hport and "-" not in hport and "$" not in hport:
                host_ports[f"{ip or '*'}:{hport}"].append(name)
        if image is None and "build" not in svc:
            report.add("no_image", "high", "Neither `image` nor `build` is set.", name, "compose services image build")
        elif image is not None:
            img = str(image)
            last = img.rsplit("/", 1)[-1]
            if "@sha256:" not in img and (":" not in last or last.endswith(":latest")):
                report.add("unpinned_image", "low", "Image tag is missing or `latest`; pin a version (or digest) for reproducible deploys.", name, "docker image tag pinning")
        for key, value in env:
            if value and is_secret_key(key) and not value.startswith("$"):
                report.add("inline_secret", "medium", f"Environment variable {key} appears to hold a literal secret (value not shown). Use secrets or an env file.", name, "compose secrets environment variables")
        for dep in dep_names:
            if dep not in names:
                report.add("unknown_dependency", "high", f"depends_on references undefined service {_s(dep, 80)!r}.", name, "compose depends_on")
            elif isinstance(depends, dict) and isinstance(depends.get(dep), dict):
                cond = depends[dep].get("condition")
                target = services.get(dep)
                if cond == "service_healthy" and not (isinstance(target, dict) and isinstance(target.get("healthcheck"), dict)):
                    report.add("healthy_condition_without_healthcheck", "high", f"Waits for {_s(dep, 80)!r} to be healthy, but that service has no healthcheck.", name, "compose startup order depends_on condition service_healthy healthcheck")
        if not summary.healthcheck:
            report.add("no_healthcheck", "info", "No healthcheck defined.", name, "dockerfile HEALTHCHECK compose healthcheck")
        if summary.restart is None:
            report.add("no_restart_policy", "info", "No restart policy; the container will not restart after a crash.", name, "docker restart policy")
        if summary.user is None:
            report.add("default_user", "low", "No `user` set; the image default is often root.", name, "docker run as non-root user")
        limits = _dig(svc, "deploy", "resources", "limits")
        if not limits and "mem_limit" not in svc:
            report.add("no_memory_limit", "info", "No memory limit set.", name, "docker resource constraints memory limit")

    for hp, owners in host_ports.items():
        if len(owners) > 1:
            report.add("host_port_conflict", "high", f"Host port {hp} is published by multiple services: {', '.join(owners)}.", None, "docker port already allocated publish ports")

    report.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.service or ""))
    return report


def inspect_compose_text(text: str, display_path: str) -> ComposeReport:
    return analyze_compose(load_compose(text), display_path)
