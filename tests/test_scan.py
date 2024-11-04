"""Tests for .scan() method."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from dpkg_scanpackages.scan_packages import DpkgScanPackages
from dpkg_scanpackages.utils import change_cwd

CURR_DIR = Path(__file__).parent
EXAMPLE_PATH = CURR_DIR / "ExamplePackages"
FOUR_MB_PATH = CURR_DIR / "4MBPackages"
ORIG_PATH = CURR_DIR / "OrigPackages"
NEWEST_PATH = CURR_DIR / "NewestPackages"
DEB_PATH = CURR_DIR / "pool/main/micromamba|1.5.8|apt.deb"


def remove_4mb_sha256(content: str) -> str:
    return "\n".join(
        line for line in content.split("\n") if not line.startswith("4MBSHA256:")
    )


def test_dpkg_scan_packages_bad_path() -> None:
    with pytest.raises(ValueError, match="^binary path /nonexisting not found$"):
        DpkgScanPackages(binary_path="/nonexisting")


def test_dpkg_scan_packages_bad_other_arch() -> None:
    with change_cwd(str(CURR_DIR)):
        scanned = DpkgScanPackages(binary_path=str(CURR_DIR), arch="amd64")
        scanned._get_packages()  # noqa: SLF001

    assert not scanned.package_list


def test_scan(orig_packages: str, four_mb_packages: str) -> None:
    output = StringIO()

    with change_cwd(str(CURR_DIR)):
        DpkgScanPackages(
            binary_path=str(CURR_DIR), multiversion=True, output=output
        ).scan()

    full_content = output.getvalue()
    strip_content = remove_4mb_sha256(full_content)

    assert strip_content == orig_packages
    assert full_content == four_mb_packages


def test_scan_no_multiversion(only_newest_packages: str) -> None:
    output = StringIO()

    with change_cwd(str(CURR_DIR)):
        DpkgScanPackages(
            binary_path=str(CURR_DIR), multiversion=False, output=output
        ).scan()

    full_content = output.getvalue()
    assert full_content == only_newest_packages


def test_scan_previous_and_return_list(
    four_mb_packages: str, capsys: pytest.CaptureFixture[str]
) -> None:
    output = StringIO()

    with change_cwd(str(CURR_DIR)):
        scanned1 = DpkgScanPackages(
            binary_path=str(CURR_DIR),
            multiversion=True,
            output=output,
            previous=str(FOUR_MB_PATH),
        )
        scanned1.scan()

    out, _ = capsys.readouterr()

    full_content = output.getvalue()

    assert full_content == four_mb_packages

    with change_cwd(str(CURR_DIR)):
        scanned2 = DpkgScanPackages(
            binary_path=str(CURR_DIR),
            multiversion=True,
            output=output,
            previous=str(FOUR_MB_PATH),
        )
        scanned2.scan(return_list=True)

    if len(scanned1.package_list) != len(scanned2.package_list):
        raise AssertionError("Length of scanned1 and scanned2 must match")

    assert all(
        a.headers == b.headers
        for a, b in zip(scanned1.package_list, scanned2.package_list)  # noqa: B905
    )
