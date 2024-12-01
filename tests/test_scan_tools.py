"""Test dpkg-scanpackages-py."""

from __future__ import annotations

import hashlib
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dpkg_scanpackages.scan_packages import (
    DpkgInfo,
    DpkgScanPackages,
    add_4mb_sha256,
    calculate_4mb_sha256,
    read_packages_file,
)
from dpkg_scanpackages.utils import DpkgInfoHeaders, multi_open_read

if TYPE_CHECKING:
    from .conftest import Helpers

# OrigPackages - Created with dpkg-scanpackages (1.12.1)
# Packages - OrigPackages with appended 4MBSHA256: lines

CURR_DIR = Path(__file__).parent
EXAMPLE_PATH = CURR_DIR / "ExamplePackages"
FOUR_MB_PATH = CURR_DIR / "4MBPackages"
ORIG_PATH = CURR_DIR / "OrigPackages"
NEWEST_PATH = CURR_DIR / "NewestPackages"
DEB_PATH = CURR_DIR / "pool/main/micromamba|1.5.8|apt.deb"


def test_dpkg_info(example_headers: dict[str, str | int], helpers: Helpers) -> None:
    example_headers["Size"] = int(example_headers["Size"])

    with helpers.change_cwd(str(CURR_DIR)):
        pkg = DpkgInfo(str(DEB_PATH.relative_to(CURR_DIR)))

    sorted_headers = dict(sorted(pkg.headers.items()))
    sorted_example_headers = dict(sorted(example_headers.items()))
    assert sorted_headers == sorted_example_headers


def test_read_packages_file(example_packages: list[dict[str, str]]) -> None:
    with EXAMPLE_PATH.open("r") as fd:
        packages_ls = read_packages_file(fd)

    assert packages_ls == example_packages


def test_read_packages_files_multiple(example_packages: list[dict[str, str]]) -> None:
    with multi_open_read((str(EXAMPLE_PATH), str(EXAMPLE_PATH))) as files:
        packages_ls = read_packages_file(files)
    assert packages_ls == example_packages + example_packages


def test_calculate_4mb_sha256(tmp_path: Path) -> None:
    (tmp_path / "small_hash.txt").write_bytes(b"a" * 4 * 1024)
    small_hash = calculate_4mb_sha256(
        str(tmp_path / "small_hash.txt"), 4 * 1024, "small_hash"
    )
    larger_size = 4 * 1024 * 1024 + 1
    (tmp_path / "large_hash.txt").write_bytes(b"a" * larger_size)
    large_hash = calculate_4mb_sha256(
        str(tmp_path / "large_hash.txt"), larger_size, "large_hash"
    )
    expected = hashlib.sha256(b"a" * 4 * 1024 * 1024).hexdigest()
    assert large_hash == expected

    assert small_hash == "small_hash"


@pytest.mark.parametrize("path", [ORIG_PATH, FOUR_MB_PATH])
def test_add_4mb(path: Path, four_mb_packages: str, helpers: Helpers) -> None:
    output = StringIO()

    with helpers.change_cwd(str(CURR_DIR)):
        add_4mb_sha256(str(path), output)

    full_content = output.getvalue()
    assert full_content == four_mb_packages


@pytest.mark.parametrize(
    ("sha256_curr", "size_curr", "sha256_prev", "size_prev", "expected"),
    [
        ("abc", 1, "abc", 1, True),
        ("abc", 1, "def", 1, False),
        ("abc", 1, "abc", 2, False),
        ("abc", 1, "def", 2, False),
        ("abc", 1, None, 1, False),
        ("abc", 1, "abc", None, False),
    ],
)
def test_is_equal(
    sha256_curr: str,
    size_curr: int,
    sha256_prev: str | None,
    size_prev: int,
    expected: bool,
) -> None:
    curr = DpkgInfoHeaders({"4MBSHA256": sha256_curr, "Size": str(size_curr)})
    prev_headers: dict[str, str] = {}
    if size_prev is not None:
        prev_headers["Size"] = str(size_prev)
    if sha256_prev is not None:
        prev_headers["4MBSHA256"] = sha256_prev
    prev = DpkgInfoHeaders(prev_headers)
    assert DpkgScanPackages._is_equal(curr, prev) == expected  # noqa: SLF001
