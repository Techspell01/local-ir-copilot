"""Curated public documentation pages used as the initial corpus.

Docker docs are published under Apache-2.0; Kubernetes docs under CC BY 4.0. Each chunk keeps
its source URL so answers can attribute and link back.
"""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_HOSTS = frozenset({"docs.docker.com", "kubernetes.io"})
LICENSES = {"docker": "Apache-2.0 (docs.docker.com)", "kubernetes": "CC BY 4.0 (kubernetes.io)"}


@dataclass(frozen=True)
class DocSource:
    url: str
    source: str  # "docker" | "kubernetes"


_DOCKER = [
    "https://docs.docker.com/reference/compose-file/services/",
    "https://docs.docker.com/reference/compose-file/networks/",
    "https://docs.docker.com/reference/compose-file/volumes/",
    "https://docs.docker.com/compose/how-tos/networking/",
    "https://docs.docker.com/compose/how-tos/startup-order/",
    "https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/",
    "https://docs.docker.com/engine/containers/start-containers-automatically/",
    "https://docs.docker.com/engine/containers/resource_constraints/",
    "https://docs.docker.com/engine/containers/run/",
    "https://docs.docker.com/engine/storage/volumes/",
    "https://docs.docker.com/engine/storage/bind-mounts/",
    "https://docs.docker.com/engine/network/",
    "https://docs.docker.com/engine/network/port-publishing/",
    "https://docs.docker.com/engine/logging/",
    "https://docs.docker.com/engine/daemon/troubleshoot/",
    "https://docs.docker.com/engine/security/",
    "https://docs.docker.com/reference/dockerfile/",
    "https://docs.docker.com/reference/cli/docker/container/logs/",
    "https://docs.docker.com/reference/cli/docker/container/inspect/",
]

_KUBERNETES = [
    "https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/",
    "https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/",
    "https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/",
    "https://kubernetes.io/docs/tasks/debug/debug-application/determine-reason-pod-failure/",
    "https://kubernetes.io/docs/tasks/debug/debug-cluster/",
    "https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/",
    "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
    "https://kubernetes.io/docs/concepts/containers/images/",
    "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
    "https://kubernetes.io/docs/concepts/services-networking/service/",
    "https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/",
    "https://kubernetes.io/docs/concepts/configuration/configmap/",
    "https://kubernetes.io/docs/concepts/configuration/secret/",
    "https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/",
    "https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/",
]

CURATED_SOURCES: tuple[DocSource, ...] = tuple(
    [DocSource(u, "docker") for u in _DOCKER] + [DocSource(u, "kubernetes") for u in _KUBERNETES]
)
