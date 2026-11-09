"""Validate user-supplied file paths against an explicit allowed root before reading them."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class PathRejected(ValueError):
    """The path is unsafe or unusable. Messages are safe to show to users."""


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    f"{p}{i}" for p in ("COM", "LPT") for i in (*range(1, 10), "¹", "²", "³")
}
_MAX_PATH_CHARS = 4096


def _norm(p: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def is_within(child: Path, root: Path) -> bool:
    c, r = _norm(child), _norm(root)
    try:
        return os.path.commonpath([c, r]) == r
    except ValueError:  # different drives on Windows
        return False


def _is_link(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(os.path, "isjunction", lambda _p: False)(p))


def resolve_root(root: str | Path) -> Path:
    """Resolve the allowed root. It must be an existing directory and not a filesystem root."""
    try:
        resolved = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathRejected("Allowed root does not exist.") from exc
    if not resolved.is_dir():
        raise PathRejected("Allowed root must be a directory.")
    if resolved.parent == resolved:
        raise PathRejected("A filesystem root is too broad to use as the allowed root.")
    return resolved


def validate_file(
    user_path: str,
    root: Path,
    *,
    max_bytes: int,
    allowed_suffixes: frozenset[str] | None = None,
) -> Path:
    """Return the resolved path of a regular file inside `root`, or raise PathRejected."""
    if not isinstance(user_path, str) or not user_path.strip():
        raise PathRejected("Path must be a non-empty string.")
    if len(user_path) > _MAX_PATH_CHARS or "\x00" in user_path:
        raise PathRejected("Path is too long or contains NUL bytes.")
    if user_path.startswith(("\\\\", "//")):
        raise PathRejected("UNC and device-namespace paths are not allowed.")

    root = resolve_root(root)
    candidate = Path(user_path)
    if not candidate.is_absolute():
        if candidate.drive:  # e.g. "C:foo" (drive-relative) on Windows
            raise PathRejected("Drive-relative paths are not allowed.")
        candidate = root / candidate
    normalized = Path(os.path.normpath(candidate))
    if not is_within(normalized, root):
        raise PathRejected("Path is outside the allowed root.")

    rel_parts = normalized.relative_to(root).parts if _norm(normalized) != _norm(root) else ()
    if not rel_parts:
        raise PathRejected("Path must name a file, not the allowed root itself.")
    current = root
    for part in rel_parts:
        stem = part.split(".")[0].strip().upper()
        if stem in _WINDOWS_RESERVED:
            raise PathRejected("Device names are not allowed.")
        if ":" in part:
            raise PathRejected("Alternate data streams are not allowed.")
        current = current / part
        if _is_link(current):
            raise PathRejected("Symbolic links and junctions are not allowed.")

    try:
        resolved = normalized.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathRejected("File not found.") from exc
    if not is_within(resolved, root):
        raise PathRejected("Path is outside the allowed root.")
    st = os.stat(resolved)
    if not stat.S_ISREG(st.st_mode):
        raise PathRejected("Not a regular file.")
    if st.st_size > max_bytes:
        raise PathRejected(f"File is larger than the {max_bytes}-byte limit.")
    if allowed_suffixes is not None and resolved.suffix.lower() not in allowed_suffixes:
        raise PathRejected(f"Unsupported file type; expected one of {sorted(allowed_suffixes)}.")
    return resolved


def read_text_limited(path: Path, max_bytes: int) -> str:
    """Read a validated file as UTF-8, re-checking type and size on the open descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PathRejected("File could not be opened.") from exc
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PathRejected("Not a regular file.")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PathRejected(f"File is larger than the {max_bytes}-byte limit.")
    if b"\x00" in data[:8192]:
        raise PathRejected("File looks binary; only text files are supported.")
    return data.decode("utf-8", errors="replace")


def load_user_file(user_path: str, root: Path, *, max_bytes: int, allowed_suffixes: frozenset[str] | None = None) -> tuple[Path, str]:
    path = validate_file(user_path, root, max_bytes=max_bytes, allowed_suffixes=allowed_suffixes)
    return path, read_text_limited(path, max_bytes)
