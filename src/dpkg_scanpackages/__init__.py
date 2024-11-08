"""Scan packages and create the Packages file for the apt repository."""

from __future__ import annotations

from dpkg_scanpackages.cli import scan_packages
from dpkg_scanpackages.scan_packages import DpkgInfo, DpkgScanPackages

__all__ = ["scan_packages", "DpkgInfo", "DpkgScanPackages"]
