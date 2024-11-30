"""Scan packages and create the Packages file for the apt repository."""

from __future__ import annotations

from dpkg_scanpackages.cli import scan_packages
from dpkg_scanpackages.scan_packages import DpkgInfo, DpkgScanPackages, add_4mb_sha256
from dpkg_scanpackages.utils import FileInputRead

__all__ = [
    "DpkgInfo",
    "DpkgScanPackages",
    "FileInputRead",
    "add_4mb_sha256",
    "scan_packages",
]
