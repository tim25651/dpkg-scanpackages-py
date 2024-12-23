"""Tests for the dpkg_scanpackages.utils module."""

# ruff: noqa: S108, PTH109
from __future__ import annotations

import os
import sys
from io import StringIO
from typing import TYPE_CHECKING

import pytest

from dpkg_scanpackages.utils import (
    DpkgInfoHeaders,
    FileInputRead,
    format_headers,
    multi_open_read,
    multi_open_write,
    write_headers,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .conftest import Helpers

DARWIN_TMP = "/private/tmp"
LINUX_TMP = "/tmp"


@pytest.fixture
def tmp() -> str:
    """Return the system's temporary directory."""
    if sys.platform not in {"darwin", "linux"}:
        raise NotImplementedError("Unsupported platform")

    return DARWIN_TMP if sys.platform == "darwin" else LINUX_TMP


def test_change_cwd(tmp: str, helpers: Helpers) -> None:
    curr_cwd = os.getcwd()

    assert curr_cwd != tmp
    with helpers.change_cwd(tmp):
        assert os.getcwd() == tmp
    assert os.getcwd() == curr_cwd


def test_dpkg_info_headers(example_packages: list[dict[str, str]]) -> None:
    for elem in example_packages:
        assert DpkgInfoHeaders(elem).headers == elem


def test_format_headers(
    example_packages: list[dict[str, str]], example_formatted: list[str]
) -> None:
    if len(example_packages) != len(example_formatted):
        raise AssertionError(
            "Length of example_packages and example_formatted must match"
        )

    for package, formatted in zip(example_packages, example_formatted):  # noqa: B905
        assert format_headers(package) == formatted

    pkg = example_packages[0]
    pkg["MISSING"] = "missing"
    assert format_headers(pkg) == example_formatted[0].strip() + "\nMISSING: missing\n"


def test_write_headers(
    example_packages: list[dict[str, str]], example_content: str
) -> None:
    with pytest.raises(ValueError, match="^No packages to write$"):
        write_headers(None, [])

    output = StringIO()
    write_headers(output, [DpkgInfoHeaders(p) for p in example_packages])
    assert output.getvalue() == example_content


def test_fileinputread(tmp_path: Path) -> None:
    (tmp_path / "test").write_bytes(b"test\n")
    (tmp_path / "test2").write_bytes(b"test2\n")

    with FileInputRead((str(tmp_path / "test"), str(tmp_path / "test2"))) as files:
        assert files.read() == "test\ntest2\n"

        with pytest.raises(NotImplementedError, match="^can only read fully$"):
            files.read(1)


def test_fileinputread_fresh(tmp_path: Path) -> None:
    (tmp_path / "test").write_bytes(b"test\n")
    with FileInputRead(str(tmp_path / "test")) as file:
        assert file.readline() == "test\n"
        with pytest.raises(ValueError, match="^can only read fresh instances$"):
            file.read()


def test_fileinputread_newline(tmp_path: Path) -> None:
    (tmp_path / "test").write_bytes(b"test\n")
    (tmp_path / "test2").write_bytes(b"test2\n")
    with FileInputRead(
        (str(tmp_path / "test"), str(tmp_path / "test2")), True
    ) as files:
        assert files.read() == "test\n\ntest2\n"


def test_multi_open_read(tmp_path: Path) -> None:
    with multi_open_read(None) as file:
        assert file == sys.stdin

    (tmp_path / "test").write_bytes(b"test\n")
    (tmp_path / "test2").write_bytes(b"test2\n")

    with multi_open_read(str(tmp_path / "test")) as file:
        assert file.read() == "test\n"

    with multi_open_read((str(tmp_path / "test"), str(tmp_path / "test2"))) as files:
        # uses add_newline=True by default from FileInputRead class
        assert files.read() == "test\n\ntest2\n"

    read_buffer = StringIO("test_buffer")

    with multi_open_read(read_buffer) as file:
        assert file.read() == "test_buffer"


def test_multi_open_write(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with multi_open_write(None) as file:
        assert file == sys.stdout
        file.write("test_stdout")

    out, _ = capsys.readouterr()
    assert out == "test_stdout"

    with multi_open_write(str(tmp_path / "test")) as file:
        file.write("test")

    content = (tmp_path / "test").read_bytes()
    assert content == b"test"

    write_buffer = StringIO()
    with multi_open_write(write_buffer) as file:
        file.write("test_buffer")

    assert write_buffer.getvalue() == "test_buffer"
