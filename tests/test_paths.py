import os
import sys
from pathlib import Path

import pytest

from ircopilot.safety.paths import PathRejected, load_user_file, resolve_root, validate_file

LIMIT = 1024


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "app.log").write_text("hello\n", encoding="utf-8")
    return tmp_path


def test_accepts_relative_and_absolute_inside_root(root: Path) -> None:
    assert validate_file("logs/app.log", root, max_bytes=LIMIT).name == "app.log"
    assert validate_file(str(root / "logs" / "app.log"), root, max_bytes=LIMIT).name == "app.log"


@pytest.mark.parametrize("bad", ["../outside.log", "logs/../../outside.log", "logs/../../../etc/passwd"])
def test_rejects_traversal(root: Path, bad: str) -> None:
    (root.parent / "outside.log").write_text("x", encoding="utf-8")
    with pytest.raises(PathRejected, match="outside the allowed root"):
        validate_file(bad, root, max_bytes=LIMIT)


def test_rejects_absolute_path_outside_root(root: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    other = tmp_path_factory.mktemp("other") / "x.log"
    other.write_text("x", encoding="utf-8")
    with pytest.raises(PathRejected, match="outside"):
        validate_file(str(other), root, max_bytes=LIMIT)


@pytest.mark.parametrize("bad", ["", "   ", "a\x00b", "\\\\server\\share\\x.log", "//server/share/x.log", "x" * 5000])
def test_rejects_malformed(root: Path, bad: str) -> None:
    with pytest.raises(PathRejected):
        validate_file(bad, root, max_bytes=LIMIT)


@pytest.mark.parametrize("name", ["NUL", "con.txt", "logs/COM1.log", "aux"])
def test_rejects_device_names(root: Path, name: str) -> None:
    with pytest.raises(PathRejected):
        validate_file(name, root, max_bytes=LIMIT)


def test_rejects_directory_missing_and_root_itself(root: Path) -> None:
    with pytest.raises(PathRejected, match="regular file"):
        validate_file("logs", root, max_bytes=LIMIT)
    with pytest.raises(PathRejected, match="not found"):
        validate_file("logs/missing.log", root, max_bytes=LIMIT)
    with pytest.raises(PathRejected):
        validate_file(".", root, max_bytes=LIMIT)


def test_size_limit_and_suffix(root: Path) -> None:
    (root / "big.log").write_bytes(b"a" * (LIMIT + 1))
    with pytest.raises(PathRejected, match="larger"):
        validate_file("big.log", root, max_bytes=LIMIT)
    with pytest.raises(PathRejected, match="Unsupported file type"):
        validate_file("logs/app.log", root, max_bytes=LIMIT, allowed_suffixes=frozenset({".yml"}))


def test_rejects_binary(root: Path) -> None:
    (root / "bin.log").write_bytes(b"ELF\x00\x01\x02")
    with pytest.raises(PathRejected, match="binary"):
        load_user_file("bin.log", root, max_bytes=LIMIT)


def test_rejects_symlinks(root: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    secret = tmp_path_factory.mktemp("secret") / "id_rsa"
    secret.write_text("key", encoding="utf-8")
    try:
        os.symlink(secret, root / "link.log")
        os.symlink(root / "logs", root / "linkdir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this system")
    with pytest.raises(PathRejected):
        validate_file("link.log", root, max_bytes=LIMIT)
    with pytest.raises(PathRejected, match="Symbolic"):
        validate_file("linkdir/app.log", root, max_bytes=LIMIT)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")
def test_rejects_junction_escape(root: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    import _winapi

    outside = tmp_path_factory.mktemp("outside")
    (outside / "secret.log").write_text("key", encoding="utf-8")
    _winapi.CreateJunction(str(outside), str(root / "junction"))
    with pytest.raises(PathRejected):
        validate_file("junction/secret.log", root, max_bytes=LIMIT)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ADS")
def test_rejects_alternate_data_stream(root: Path) -> None:
    with pytest.raises(PathRejected):
        validate_file("logs/app.log:hidden", root, max_bytes=LIMIT)


def test_root_must_be_directory_and_not_filesystem_root(root: Path) -> None:
    with pytest.raises(PathRejected, match="too broad"):
        resolve_root(Path(root.anchor))
    with pytest.raises(PathRejected):
        resolve_root(root / "logs" / "app.log")
    with pytest.raises(PathRejected):
        resolve_root(root / "nope")
